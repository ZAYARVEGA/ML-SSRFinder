#!/usr/bin/env python3
"""
Neural Forger - HTTP Response ML Analysis Layer

Loads 3 trained ML models (SVM-RBF, XGBoost, Random Forest) that analyze
HTTP responses after payload injection to confirm SSRF vulnerabilities.

This is the ACTIVE scan layer — it requires actual server interaction
(payloads must be injected first via -p). It complements the passive
request-based ML in neuralforger-ml.py.

Public API:
    ResponseMLAnalyzer.analyze(response_data) -> Optional[ResponseMLResult]
    ResponseMLAnalyzer.is_available() -> bool
"""

import os
import sys
import time
import pickle
import warnings
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

import numpy as np

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

try:
    from colorama import Fore, Style
except ImportError:
    class _Stub:
        def __getattr__(self, _):
            return ""
    Fore = Style = _Stub()


# ============================================================================
# Model file definitions
# ============================================================================

MODEL_FILES = {
    'svm_rbf':       'svm_rbf_response.pkl',
    'xgboost':       'xgboost_response.pkl',
    'random_forest': 'random_forest_response.pkl',
}


# ============================================================================
# Response body analysis helpers
# ============================================================================

_AWS_METADATA_KEYWORDS = [
    'ami-id', 'ami-launch-index', 'instance-id',
    'local-ipv4', 'public-ipv4', 'security-groups',
    'identity-credentials', 'instance-type',
]

_CREDENTIAL_KEYWORDS = [
    'accesskeyid', 'secretaccesskey', 'aws-hmac',
    '"code":"success"', 'expiration',
]

_INTERNAL_INFO_KEYWORDS = [
    'og:title', 'service_name', 'internal', 'intranet',
    'phpinfo()', 'server_software', 'document_root',
    'actuator/health', 'server-status', 'nginx_status',
    'redis_version', 'elasticsearch',
]

_UNUSUAL_HEADER_INDICATORS = [
    'authorization', 'x-forwarded-for', 'x-envoy-upstream-service-time',
    'x-amz-request-id', 'traceparent', 'x-forwarded-host', 'ec2ws',
]

# System file patterns (/etc/passwd, /etc/shadow, etc.)
_SYSTEM_FILE_KEYWORDS = [
    'root:x:0:0:', 'root:*:0:0:', 'daemon:x:1:1:',
    'nobody:x:', '/bin/bash', '/bin/sh', '/sbin/nologin',
    'root:$', 'root:!', 'www-data:x:',
]

# Database / config leak patterns
_DB_CONFIG_KEYWORDS = [
    'db_password', 'database_url', 'mysql://', 'postgres://',
    'mongodb://', 'redis://', 'jdbc:', 'sqlserver://',
    'db_host', 'db_user', 'db_name', 'database_password',
    'mysecretdbpass', 'dbpass',
]

# Private key patterns
_PRIVATE_KEY_KEYWORDS = [
    '-----begin rsa private key-----',
    '-----begin openssh private key-----',
    '-----begin private key-----',
    '-----begin ec private key-----',
    '-----begin certificate-----',
]

# WAF / block indicators
_WAF_BLOCK_KEYWORDS = [
    'request blocked',         # "Request Blocked" in error div
    'blocked: private',        # "Blocked: Private/Internal IP detected"
    'blocked: internal',       # "Blocked: Internal IP"
    'blocked: loopback',       # "Blocked: Loopback address"
    'blocked: restricted',     # "Blocked: Restricted address"
    'blocked: invalid',        # "Blocked: Invalid URL"
    'url rejected',
    'request rejected',
    'ssrf attack detected',
    'ssrf attempt blocked',
    'request filtered',
    'address not allowed',
    'restricted address detected',
    'private/internal ip detected',
    'internal ip detected',
    'blocked by security policy',
    'web application firewall',
    'url not permitted',
    'ip address is not allowed',
    'failed to connect',       # curl/fetch failures shown to user
]

# .env / config file patterns
_ENV_CONFIG_KEYWORDS = [
    'aws_access_key_id=', 'aws_secret_access_key=',
    'api_key=', 'secret_key=', 'private_key=',
    'smtp_password=', 'database_url=',
]

# GCP metadata patterns
_GCP_META_KEYWORDS = [
    'computemetadata', 'metadata.google.internal',
    'v1/instance/', 'v1/project/',
    'service-accounts/default/token',
]


def _has_aws_metadata(body_text: str) -> bool:
    """Check if response body contains AWS metadata indicators (>=3 keywords)."""
    return sum(1 for kw in _AWS_METADATA_KEYWORDS if kw in body_text) >= 3


def _has_credentials(body_text: str) -> bool:
    """Check if response body contains credential-related keywords."""
    return any(kw in body_text for kw in _CREDENTIAL_KEYWORDS)


def _has_error_json(body_text: str) -> bool:
    """Check if response body contains JSON error structure."""
    return (
        ('"error"' in body_text or '"code"' in body_text) and
        ('"message"' in body_text or '"details"' in body_text)
    )


def _has_bearer(body_text: str) -> bool:
    """Check if response body contains bearer token references."""
    return 'authorization: bearer' in body_text or 'bearer ' in body_text


def _has_internal_info(body_text: str) -> bool:
    """Check if response body contains internal service information."""
    return any(kw in body_text for kw in _INTERNAL_INFO_KEYWORDS)


def _has_system_file(body_text: str) -> bool:
    """Check if response contains system file content (/etc/passwd, etc.)."""
    return sum(1 for kw in _SYSTEM_FILE_KEYWORDS if kw in body_text) >= 2


def _has_db_config(body_text: str) -> bool:
    """Check if response contains database/config leak indicators."""
    return any(kw in body_text for kw in _DB_CONFIG_KEYWORDS)


def _has_private_key(body_text: str) -> bool:
    """Check if response contains private key material."""
    return any(kw in body_text for kw in _PRIVATE_KEY_KEYWORDS)


def _has_waf_block(body_text: str) -> bool:
    """Check if response indicates WAF/filter blocked the request.

    Uses specific multi-word patterns and requires the block indicator
    to appear near result/error content, not in navigation or templates.
    """
    # First check: any specific block phrase present?
    found = any(kw in body_text for kw in _WAF_BLOCK_KEYWORDS)
    if not found:
        return False

    # Second check: make sure it's in a result/error context,
    # not just the word "blocked" in a navigation menu
    # If we find block keywords AND the page also has real external
    # content (JSON data, external HTML), it's NOT blocked
    external_content_signs = [
        '"login":', '"id":', '"url":',     # JSON API response
        '"name":', '"email":',             # JSON data
        '<!doctype', '<html',              # could be proxied HTML
    ]
    # Count how many external content indicators exist
    ext_hits = sum(1 for s in external_content_signs if s in body_text)
    # If the body has substantial external data, it's not a block page
    if ext_hits >= 3:
        return False

    return True


def _has_env_config(body_text: str) -> bool:
    """Check if response contains .env / config file secrets."""
    return sum(1 for kw in _ENV_CONFIG_KEYWORDS if kw in body_text) >= 2


def _has_gcp_metadata(body_text: str) -> bool:
    """Check if response contains GCP metadata indicators."""
    return sum(1 for kw in _GCP_META_KEYWORDS if kw in body_text) >= 2


def _detect_unusual_headers(headers: dict) -> list:
    """Detect unusual/security-relevant headers in the response."""
    return [
        f"{k}: {v}" for k, v in headers.items()
        if any(u in k.lower() for u in _UNUSUAL_HEADER_INDICATORS)
    ]


def _classify_body_structure(body_text: str, headers: dict) -> str:
    """Classify the response body structure for ML feature extraction."""
    ct = (headers.get('Content-Type') or headers.get('content-type', '')).lower()
    if _has_aws_metadata(body_text):
        return 'metadata_listing'
    if _has_credentials(body_text):
        return 'credentials_json'
    if _has_error_json(body_text):
        return 'error_json'
    if 'image' in ct:
        return 'binary_image'
    if 'xml' in ct:
        return 'xml_response'
    if 'html' in ct:
        return 'html_public_page'
    if 'json' in ct:
        return 'success_json'
    if ct.startswith('text/plain'):
        return 'text_plain_legitimate'
    return 'empty'


# ============================================================================
# External SSRF detection helpers
# ============================================================================

# Internal IP patterns that are NOT external
_INTERNAL_IP_PATTERNS = [
    '127.0.0.1', 'localhost', '0.0.0.0',
    '169.254.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
    '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
    '192.168.', '[::1]', '[::ffff:', '[0:0:0:0',
    '2852039166',            # decimal for 169.254.169.254
    '0xa9fe', '0251.0376',  # hex/octal for 169.254.x.x
    'metadata.google.internal',
]


def _is_external_url(payload: str) -> bool:
    """Check if a payload URL targets an external (non-internal) host."""
    payload_lower = payload.lower().strip()

    # Must look like a URL
    if not any(payload_lower.startswith(s) for s in ['http://', 'https://']):
        return False

    # Check if it matches any internal pattern
    for pattern in _INTERNAL_IP_PATTERNS:
        if pattern in payload_lower:
            return False

    # file:// is not external
    if payload_lower.startswith('file://'):
        return False

    return True


def _detect_external_content(body_text: str, payload: str) -> str:
    """
    Detect if the response body contains content fetched from an external URL.

    Returns a description string if external content is detected, empty string otherwise.
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(payload)
        domain = (parsed.hostname or '').lower()
    except Exception:
        domain = ''

    indicators_found = []

    # Check 1: Response contains JSON API data (common for external APIs)
    json_api_signs = ['"id":', '"url":', '"type":', '"name":',
                      '"created_at":', '"login":', '"node_id":',
                      '"html_url":', '"avatar_url":']
    json_hits = sum(1 for s in json_api_signs if s in body_text)
    if json_hits >= 3:
        indicators_found.append('external JSON API data')

    # Check 2: Response contains the external domain name in content
    # (proves the server actually fetched from that domain)
    if domain and len(domain) > 4 and domain in body_text:
        indicators_found.append(f'references to {domain}')

    # Check 3: Response contains HTTP headers from external service
    # embedded in the body (some apps show full response)
    external_header_signs = ['x-github', 'x-ratelimit', 'cf-ray',
                             'x-powered-by', 'x-request-id',
                             'access-control-allow-origin']
    header_hits = sum(1 for s in external_header_signs if s in body_text)
    if header_hits >= 1:
        indicators_found.append('external service headers')

    # Check 4: Response received content (for generic detection)
    # Look for "response received" type indicators from the lab
    if 'response received' in body_text or 'response content' in body_text:
        if json_hits >= 2 or (domain and domain in body_text):
            indicators_found.append('server displayed fetched content')

    # Require at least 2 different indicators to confirm external fetch
    # (domain alone in a form field is not enough)
    if len(indicators_found) >= 2:
        return ', '.join(indicators_found)
    return ''


def _response_data_to_dict(response_data) -> dict:
    """
    Convert a ResponseData object into the dict format that
    extract_response_features() expects.

    Maps runtime ResponseData fields to the training-time schema.
    """
    headers = response_data.headers or {}
    content = response_data.content or b''
    if isinstance(content, str):
        body_text = content.lower()
    else:
        body_text = content.decode('utf-8', errors='ignore').lower()

    return {
        'status_code':              response_data.status_code,
        'response_size_bytes':      response_data.response_size_bytes,
        'response_time_ms':         response_data.response_time_ms,
        'server_header':            headers.get('Server') or headers.get('server'),
        'content_type':             headers.get('Content-Type') or headers.get('content-type', ''),
        'unusual_headers':          _detect_unusual_headers(headers),
        'body_has_aws_metadata':    _has_aws_metadata(body_text),
        'body_has_credentials':     _has_credentials(body_text),
        'body_has_oob_echo':        False,   # cannot auto-detect at runtime
        'body_has_error_json':      _has_error_json(body_text),
        'body_has_bearer_token':    _has_bearer(body_text),
        'body_has_internal_service_info': _has_internal_info(body_text),
        'body_has_system_file':     _has_system_file(body_text),
        'body_has_db_config':       _has_db_config(body_text),
        'body_has_private_key':     _has_private_key(body_text),
        'body_has_waf_block':       _has_waf_block(body_text),
        'body_has_env_config':      _has_env_config(body_text),
        'body_has_gcp_metadata':    _has_gcp_metadata(body_text),
        'body_structure':           _classify_body_structure(body_text, headers),
    }


# ============================================================================
# Feature extraction (mirrors train_response_models.py extract_features)
# ============================================================================

def extract_response_features(response_dict: dict) -> dict:
    """
    Extract the 33 ML features from an HTTP response dict.

    This function replicates the exact logic from train_response_models.py's
    extract_features() so that runtime feature vectors match what the models
    were trained on.

    Args:
        response_dict: Dict produced by _response_data_to_dict().

    Returns:
        Dict mapping feature names to numeric values.
    """
    features = {}

    # --- Status code features ---
    status = response_dict.get('status_code')
    features['status_is_200'] = 1 if status == 200 else 0
    features['status_is_redirect'] = 1 if status and 300 <= status < 400 else 0
    features['status_is_error'] = 1 if status and status >= 400 else 0
    features['status_is_server_error'] = 1 if status and 500 <= status < 600 else 0

    # --- Response size features ---
    size = response_dict.get('response_size_bytes') or 0
    features['response_size_bytes'] = size
    features['size_is_zero'] = 1 if size == 0 else 0
    features['size_is_small'] = 1 if 0 < size <= 500 else 0
    features['size_is_medium'] = 1 if 500 < size <= 5000 else 0
    features['size_is_large'] = 1 if size > 5000 else 0

    # --- Timing features ---
    timing = response_dict.get('response_time_ms') or 0
    features['response_time_ms'] = timing
    features['timing_is_fast'] = 1 if timing < 500 else 0
    features['timing_is_slow'] = 1 if timing > 3000 else 0

    # --- Content-Type features ---
    ct = (response_dict.get('content_type') or '').lower()
    features['ct_is_json'] = 1 if 'json' in ct else 0
    features['ct_is_html'] = 1 if 'html' in ct else 0
    features['ct_is_xml'] = 1 if 'xml' in ct else 0
    features['ct_is_text'] = 1 if ct.startswith('text/plain') else 0
    features['ct_is_image'] = 1 if 'image' in ct else 0

    # --- Server header feature ---
    features['has_server_header'] = 1 if response_dict.get('server_header') else 0

    # --- Body content indicator features ---
    features['body_has_aws_metadata'] = 1 if response_dict.get('body_has_aws_metadata') else 0
    features['body_has_credentials'] = 1 if response_dict.get('body_has_credentials') else 0
    features['body_has_oob_echo'] = 1 if response_dict.get('body_has_oob_echo') else 0
    features['body_has_error_json'] = 1 if response_dict.get('body_has_error_json') else 0
    features['body_has_bearer_token'] = 1 if response_dict.get('body_has_bearer_token') else 0
    features['body_has_internal_service_info'] = 1 if response_dict.get('body_has_internal_service_info') else 0

    # --- NEW: Extended body content features ---
    features['body_has_system_file'] = 1 if response_dict.get('body_has_system_file') else 0
    features['body_has_db_config'] = 1 if response_dict.get('body_has_db_config') else 0
    features['body_has_private_key'] = 1 if response_dict.get('body_has_private_key') else 0
    features['body_has_waf_block'] = 1 if response_dict.get('body_has_waf_block') else 0
    features['body_has_env_config'] = 1 if response_dict.get('body_has_env_config') else 0
    features['body_has_gcp_metadata'] = 1 if response_dict.get('body_has_gcp_metadata') else 0

    # --- Unusual headers feature ---
    unusual = response_dict.get('unusual_headers') or []
    features['unusual_header_count'] = len(unusual)
    features['has_unusual_headers'] = 1 if len(unusual) > 0 else 0

    # --- Body structure one-hot features ---
    structure = response_dict.get('body_structure', 'empty')
    for cat in ['metadata_listing', 'credentials_json', 'error_json',
                'html_public_page', 'success_json', 'empty']:
        features[f'structure_{cat}'] = 1 if structure == cat else 0

    return features


# ============================================================================
# Response Content Analysis (WAF detection + sensitive data discovery)
# ============================================================================

# --- Block/WAF indicators (lower confidence) ---
# These must be specific multi-word phrases to avoid matching
# words that appear naturally in HTML templates (like "blocked" in navigation)
_BLOCK_INDICATORS = [
    'request blocked',
    'blocked: private',
    'blocked: internal',
    'blocked: loopback',
    'blocked: restricted',
    'blocked: invalid',
    'url rejected',
    'request rejected',
    'ssrf attack detected',
    'ssrf attempt blocked',
    'request filtered',
    'address not allowed',
    'restricted address detected',
    'private/internal ip detected',
    'internal ip detected',
    'blocked by security',
    'web application firewall',
    'url not permitted',
    'ip address is not allowed',
    'security violation',
    'whitelisted only',
    'failed to connect',
]

# --- AWS credential patterns ---
_AWS_CRED_PATTERNS = [
    ('accesskeyid', 'AWS Access Key ID'),
    ('secretaccesskey', 'AWS Secret Access Key'),
    ('sessiontoken', 'AWS Session Token'),
    ('"code" : "success"', 'AWS IAM Success Response'),
    ('"code":"success"', 'AWS IAM Success Response'),
    ('arn:aws:iam::', 'AWS IAM ARN'),
    ('arn:aws:sts::', 'AWS STS ARN'),
]

# --- AWS metadata patterns ---
_AWS_META_PATTERNS = [
    ('ami-id', 'AWS AMI ID'),
    ('instance-id', 'AWS Instance ID'),
    ('instance-type', 'AWS Instance Type'),
    ('local-ipv4', 'AWS Local IPv4'),
    ('public-ipv4', 'AWS Public IPv4'),
    ('security-groups', 'AWS Security Groups'),
    ('availability-zone', 'AWS Availability Zone'),
    ('identity-credentials', 'AWS Identity Credentials'),
    ('iam/security-credentials', 'AWS IAM Credentials Path'),
    ('ami-launch-index', 'AWS AMI Launch Index'),
    ('mac', 'AWS MAC Address'),
    ('hostname', 'AWS Instance Hostname'),
]

# --- /etc/passwd and system file patterns ---
_SYSTEM_FILE_PATTERNS = [
    ('root:x:0:0:', '/etc/passwd - root entry'),
    ('root:*:0:0:', '/etc/passwd - root entry (BSD)'),
    ('daemon:x:1:1:', '/etc/passwd - daemon entry'),
    ('nobody:x:', '/etc/passwd - nobody entry'),
    ('/bin/bash', '/etc/passwd - shell reference'),
    ('/bin/sh', '/etc/passwd - shell reference'),
    ('/sbin/nologin', '/etc/passwd - nologin shell'),
    ('root:$', '/etc/shadow - root hash'),
    ('root:!', '/etc/shadow - locked root'),
]

# --- SSH/crypto key patterns ---
_KEY_PATTERNS = [
    ('-----begin rsa private key-----', 'RSA Private Key'),
    ('-----begin openssh private key-----', 'OpenSSH Private Key'),
    ('-----begin dsa private key-----', 'DSA Private Key'),
    ('-----begin ec private key-----', 'EC Private Key'),
    ('-----begin private key-----', 'PKCS8 Private Key'),
    ('-----begin certificate-----', 'X.509 Certificate'),
    ('-----begin pgp private key-----', 'PGP Private Key'),
]

# --- GCP metadata patterns ---
_GCP_META_PATTERNS = [
    ('computemetadata', 'GCP Compute Metadata'),
    ('metadata.google.internal', 'GCP Metadata Endpoint'),
    ('v1/instance/', 'GCP Instance Metadata'),
    ('v1/project/', 'GCP Project Metadata'),
    ('service-accounts/default/token', 'GCP Service Account Token'),
]

# --- Azure metadata patterns ---
_AZURE_META_PATTERNS = [
    ('"compute":', 'Azure Compute Metadata'),
    ('metadata/instance', 'Azure Instance Metadata'),
    ('"subscriptionid":', 'Azure Subscription ID'),
    ('"resourcegroupname":', 'Azure Resource Group'),
    ('api-version=', 'Azure API Version Parameter'),
]

# --- Database / config patterns ---
_DATA_LEAK_PATTERNS = [
    ('mysql://', 'MySQL Connection String'),
    ('postgres://', 'PostgreSQL Connection String'),
    ('mongodb://', 'MongoDB Connection String'),
    ('redis://', 'Redis Connection String'),
    ('db_password', 'Database Password Reference'),
    ('database_url', 'Database URL Reference'),
    ('jdbc:', 'JDBC Connection String'),
    ('sqlserver://', 'SQL Server Connection String'),
]

# --- .env / config file patterns ---
_ENV_PATTERNS = [
    ('aws_access_key_id=', 'AWS Key in .env'),
    ('aws_secret_access_key=', 'AWS Secret in .env'),
    ('api_key=', 'API Key in .env'),
    ('secret_key=', 'Secret Key in .env'),
    ('database_url=', 'Database URL in .env'),
    ('smtp_password=', 'SMTP Password in .env'),
    ('private_key=', 'Private Key in .env'),
]

# --- Kubernetes / Docker patterns ---
_K8S_PATTERNS = [
    ('apiversion:', 'Kubernetes API Version'),
    ('kind: secret', 'Kubernetes Secret'),
    ('kind: configmap', 'Kubernetes ConfigMap'),
    ('kubernetes.default.svc', 'Kubernetes Service DNS'),
    ('serviceaccount/token', 'Kubernetes SA Token'),
]

# --- Internal service indicators ---
_INTERNAL_SERVICE_PATTERNS = [
    ('phpinfo()', 'PHP Info Page'),
    ('server_software', 'Server Software Disclosure'),
    ('document_root', 'Document Root Disclosure'),
    ('x-debug-token', 'Debug Token Header'),
    ('actuator/health', 'Spring Actuator Health'),
    ('server-status', 'Apache Server Status'),
    ('/nginx_status', 'Nginx Status Page'),
    ('elasticsearch', 'Elasticsearch Service'),
    ('redis_version', 'Redis Version Info'),
    ('consul', 'Consul Service Discovery'),
]


@dataclass
class ContentFinding:
    """A single sensitive content finding in the response body."""
    category: str           # 'aws_credentials', 'aws_metadata', 'system_file', etc.
    description: str        # Human-readable description
    severity: str           # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    confidence_boost: float # How much to boost confidence (0-100)


@dataclass
class ContentAnalysis:
    """Complete content analysis results for a response."""
    is_blocked: bool                    # WAF/filter blocked the request
    block_reason: str                   # Why it was blocked
    findings: List[ContentFinding]      # Sensitive data found
    confidence_modifier: float          # Net confidence adjustment (-100 to +100)
    finding_categories: List[str]       # Unique categories found


def analyze_response_content(
    body: bytes,
    headers: Optional[dict] = None,
    payload: str = '',
) -> ContentAnalysis:
    """
    Analyze HTTP response body for WAF blocks and sensitive data leaks.

    This is independent of the ML models — it uses pattern matching to detect
    concrete indicators of SSRF success or failure in the response content.

    Args:
        body: Raw response body bytes.
        headers: Response headers dict.
        payload: The payload that was sent (for context).

    Returns:
        ContentAnalysis with block detection and sensitive data findings.
    """
    if isinstance(body, bytes):
        body_text = body.decode('utf-8', errors='ignore').lower()
    else:
        body_text = (body or '').lower()

    headers = headers or {}
    findings: List[ContentFinding] = []
    is_blocked = False
    block_reason = ''

    # ----- Step 1: Detect WAF/filter blocks (context-aware) -----
    for indicator in _BLOCK_INDICATORS:
        if indicator in body_text:
            # Verify it's in an error/result context, not just in page chrome
            # Check: does the response ALSO contain external content?
            # If yes, the request wasn't actually blocked
            external_data_signs = [
                '"login":', '"id":', '"url":', '"name":', '"email":',
                '"type":', '"node_id":', '"created_at":',
            ]
            ext_count = sum(1 for s in external_data_signs if s in body_text)
            if ext_count >= 3:
                # Response has real JSON data — not a block page
                break

            is_blocked = True
            import re
            # Extract block reason starting from the indicator forward
            idx = body_text.find(indicator)
            raw_context = body_text[idx:idx+120]
            # Strip HTML tags
            clean = re.sub(r'<[^>]+>', ' ', raw_context)
            # Collapse whitespace
            clean = re.sub(r'\s+', ' ', clean).strip()
            # Capitalize first letter
            if clean:
                clean = clean[0].upper() + clean[1:]
            block_reason = clean[:100] if clean else indicator.capitalize()
            break

    # ----- Step 2: Scan for sensitive data -----

    # AWS Credentials (CRITICAL)
    aws_cred_hits = [(pat, desc) for pat, desc in _AWS_CRED_PATTERNS if pat in body_text]
    if len(aws_cred_hits) >= 2:
        findings.append(ContentFinding(
            category='aws_credentials',
            description=f"AWS credentials detected: {', '.join(d for _, d in aws_cred_hits)}",
            severity='CRITICAL',
            confidence_boost=45.0,
        ))

    # AWS Metadata (HIGH)
    aws_meta_hits = [(pat, desc) for pat, desc in _AWS_META_PATTERNS if pat in body_text]
    if len(aws_meta_hits) >= 3:
        findings.append(ContentFinding(
            category='aws_metadata',
            description=f"AWS metadata fields found ({len(aws_meta_hits)} indicators)",
            severity='HIGH',
            confidence_boost=35.0,
        ))

    # System files - /etc/passwd, /etc/shadow (CRITICAL)
    sys_hits = [(pat, desc) for pat, desc in _SYSTEM_FILE_PATTERNS if pat in body_text]
    if len(sys_hits) >= 2:
        findings.append(ContentFinding(
            category='system_file',
            description=f"System file content detected: {sys_hits[0][1]}",
            severity='CRITICAL',
            confidence_boost=45.0,
        ))

    # SSH/crypto keys (CRITICAL)
    for pat, desc in _KEY_PATTERNS:
        if pat in body_text:
            findings.append(ContentFinding(
                category='private_key',
                description=f"Private key found: {desc}",
                severity='CRITICAL',
                confidence_boost=45.0,
            ))
            break  # One is enough

    # GCP Metadata (HIGH)
    gcp_hits = [(pat, desc) for pat, desc in _GCP_META_PATTERNS if pat in body_text]
    if len(gcp_hits) >= 2:
        findings.append(ContentFinding(
            category='gcp_metadata',
            description=f"GCP metadata detected ({len(gcp_hits)} indicators)",
            severity='HIGH',
            confidence_boost=35.0,
        ))

    # Azure Metadata (HIGH)
    azure_hits = [(pat, desc) for pat, desc in _AZURE_META_PATTERNS if pat in body_text]
    if len(azure_hits) >= 2:
        findings.append(ContentFinding(
            category='azure_metadata',
            description=f"Azure metadata detected ({len(azure_hits)} indicators)",
            severity='HIGH',
            confidence_boost=35.0,
        ))

    # Database connection strings (HIGH)
    db_hits = [(pat, desc) for pat, desc in _DATA_LEAK_PATTERNS if pat in body_text]
    if db_hits:
        findings.append(ContentFinding(
            category='database_leak',
            description=f"Database info exposed: {db_hits[0][1]}",
            severity='HIGH',
            confidence_boost=30.0,
        ))

    # .env / config files (HIGH)
    env_hits = [(pat, desc) for pat, desc in _ENV_PATTERNS if pat in body_text]
    if len(env_hits) >= 2:
        findings.append(ContentFinding(
            category='config_leak',
            description=f"Config/env file content ({len(env_hits)} secrets found)",
            severity='HIGH',
            confidence_boost=35.0,
        ))

    # Kubernetes/Docker (HIGH)
    k8s_hits = [(pat, desc) for pat, desc in _K8S_PATTERNS if pat in body_text]
    if len(k8s_hits) >= 2:
        findings.append(ContentFinding(
            category='k8s_secrets',
            description=f"Kubernetes/Docker secrets detected ({len(k8s_hits)} indicators)",
            severity='HIGH',
            confidence_boost=30.0,
        ))

    # Internal services (MEDIUM)
    internal_hits = [(pat, desc) for pat, desc in _INTERNAL_SERVICE_PATTERNS if pat in body_text]
    if internal_hits:
        findings.append(ContentFinding(
            category='internal_service',
            description=f"Internal service exposed: {internal_hits[0][1]}",
            severity='MEDIUM',
            confidence_boost=20.0,
        ))

    # Bearer tokens in body (HIGH)
    if 'bearer ' in body_text or 'authorization: bearer' in body_text:
        findings.append(ContentFinding(
            category='bearer_token',
            description='Bearer token found in response body',
            severity='HIGH',
            confidence_boost=30.0,
        ))

    # ----- Step 2b: External SSRF detection -----
    # If the payload targets an external URL and the response contains
    # data that clearly came from that external service, the SSRF
    # mechanism is confirmed (server-side fetch works)
    if payload and not is_blocked and not findings:
        _is_external = _is_external_url(payload)
        if _is_external:
            # Check if response body contains external content
            # (JSON API data, external HTML, etc.)
            ext_indicators = _detect_external_content(body_text, payload)
            if ext_indicators:
                findings.append(ContentFinding(
                    category='external_ssrf',
                    description=f"SSRF mechanism confirmed: server fetched external URL ({ext_indicators})",
                    severity='MEDIUM',
                    confidence_boost=15.0,
                ))

    # ----- Step 3: Calculate net confidence modifier -----
    if is_blocked and not findings:
        # Blocked and no sensitive data = definite false positive
        confidence_modifier = -70.0
    elif is_blocked and findings:
        # Blocked but somehow has sensitive data (unlikely but handle it)
        confidence_modifier = sum(f.confidence_boost for f in findings) * 0.5
    elif findings:
        # Not blocked + sensitive data found = real SSRF
        # Use the highest boost (not cumulative to avoid over-inflation)
        # but add small bonuses for multiple finding categories
        boosts = sorted([f.confidence_boost for f in findings], reverse=True)
        confidence_modifier = boosts[0]
        for extra in boosts[1:]:
            confidence_modifier += extra * 0.25  # diminishing returns
        confidence_modifier = min(50.0, confidence_modifier)
    else:
        # Not blocked, no findings = neutral
        confidence_modifier = 0.0

    categories = list(set(f.category for f in findings))

    return ContentAnalysis(
        is_blocked=is_blocked,
        block_reason=block_reason,
        findings=findings,
        confidence_modifier=confidence_modifier,
        finding_categories=categories,
    )


# ============================================================================
# Result data classes
# ============================================================================

@dataclass
class ResponseMLVerdict:
    """Per-model prediction result."""
    model_name: str          # 'svm_rbf' | 'xgboost' | 'random_forest'
    prediction: bool         # True = SSRF detected
    confidence_pct: float    # model's confidence 0-100
    label: str               # 'positive' | 'negative'
    accuracy_loo: float      # model's LOO accuracy from training


@dataclass
class ResponseMLResult:
    """Ensemble result from all loaded response models."""
    verdicts: List[ResponseMLVerdict]
    ensemble_positive: bool       # majority vote (>=2 of 3)
    ensemble_confidence: float    # weighted average by LOO accuracy
    positive_count: int
    negative_count: int
    analysis_time_ms: float


# ============================================================================
# Response ML Analyzer
# ============================================================================

class ResponseMLAnalyzer:
    """
    Loads trained response ML models and runs ensemble prediction
    on HTTP responses received after payload injection.
    """

    def __init__(self, models_dir: str = '.'):
        """
        Load all available response ML models.

        Searches for .pkl files in multiple candidate directories:
        1. The explicitly provided models_dir
        2. The directory containing this module (neuralforger-response-ml.py)
        3. The current working directory
        4. A 'models/' subdirectory under each of the above

        Args:
            models_dir: Primary directory to search for .pkl model files.
        """
        self._models: Dict[str, dict] = {}
        self._load_errors: List[str] = []

        # Build list of candidate directories to search
        _this_dir = os.path.dirname(os.path.abspath(__file__))
        _cwd = os.getcwd()

        search_dirs = []
        for d in [models_dir, _this_dir, _cwd]:
            d_abs = os.path.abspath(d)
            if d_abs not in search_dirs:
                search_dirs.append(d_abs)
            models_sub = os.path.join(d_abs, 'models')
            if models_sub not in search_dirs:
                search_dirs.append(models_sub)

        for model_name, filename in MODEL_FILES.items():
            loaded = False
            tried_paths = []

            for search_dir in search_dirs:
                filepath = os.path.join(search_dir, filename)
                tried_paths.append(filepath)

                if not os.path.isfile(filepath):
                    continue

                try:
                    with open(filepath, 'rb') as f:
                        model_data = pickle.load(f)

                    # Validate expected structure
                    required_keys = {'model', 'scaler', 'feature_names'}
                    if not required_keys.issubset(model_data.keys()):
                        missing = required_keys - model_data.keys()
                        self._load_errors.append(
                            f"{model_name}: missing keys {missing} in pkl"
                        )
                        continue

                    self._models[model_name] = model_data
                    print(f"[*] Response ML: Loaded {model_name} "
                          f"({filepath})", file=sys.stderr)
                    loaded = True
                    break

                except Exception as exc:
                    self._load_errors.append(
                        f"{model_name}: load error from {filepath} ({exc})"
                    )

            if not loaded and model_name not in [e.split(':')[0] for e in self._load_errors]:
                self._load_errors.append(
                    f"{model_name}: file not found. Searched:\n"
                    + "\n".join(f"         - {p}" for p in tried_paths)
                )

        if self._load_errors:
            for err in self._load_errors:
                print(f"[!] Response ML warning: {err}", file=sys.stderr)

        if self._models:
            names = ', '.join(self._models.keys())
            print(f"[*] Response ML: {len(self._models)} model(s) ready "
                  f"[{names}]", file=sys.stderr)
        else:
            print("[!] Response ML: No models loaded. "
                  "Response ML analysis unavailable.", file=sys.stderr)

    def is_available(self) -> bool:
        """Returns True if at least one model loaded successfully."""
        return len(self._models) > 0

    def analyze(self, response_data) -> Optional[ResponseMLResult]:
        """
        Run all loaded models on an HTTP response and return ensemble result.

        Args:
            response_data: ResponseData object (or any object with
                status_code, response_size_bytes, response_time_ms,
                headers, content attributes).

        Returns:
            ResponseMLResult with per-model verdicts and ensemble,
            or None if no models are loaded.
        """
        if not self._models:
            return None

        if not HAS_PANDAS:
            print("[!] Response ML: pandas not available, cannot analyze.",
                  file=sys.stderr)
            return None

        start_time = time.perf_counter()

        # Convert response data to feature dict
        response_dict = _response_data_to_dict(response_data)
        raw_features = extract_response_features(response_dict)

        verdicts: List[ResponseMLVerdict] = []

        for model_name, model_data in self._models.items():
            try:
                verdict = self._predict_single(
                    model_name, model_data, raw_features
                )
                verdicts.append(verdict)
            except Exception as exc:
                print(f"[!] Response ML: {model_name} prediction failed: {exc}",
                      file=sys.stderr)

        if not verdicts:
            return None

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Ensemble: majority vote
        positive_count = sum(1 for v in verdicts if v.prediction)
        negative_count = len(verdicts) - positive_count
        ensemble_positive = positive_count >= 2

        # Ensemble confidence: weighted average by LOO accuracy
        total_weight = sum(v.accuracy_loo for v in verdicts)
        if total_weight > 0:
            ensemble_confidence = sum(
                v.confidence_pct * (v.accuracy_loo / total_weight)
                for v in verdicts
            )
        else:
            ensemble_confidence = sum(v.confidence_pct for v in verdicts) / len(verdicts)

        return ResponseMLResult(
            verdicts=verdicts,
            ensemble_positive=ensemble_positive,
            ensemble_confidence=round(ensemble_confidence, 1),
            positive_count=positive_count,
            negative_count=negative_count,
            analysis_time_ms=round(elapsed_ms, 2),
        )

    def _predict_single(
        self,
        model_name: str,
        model_data: dict,
        raw_features: dict,
    ) -> ResponseMLVerdict:
        """
        Run a single model prediction.

        Args:
            model_name: Name key for the model.
            model_data: Loaded pkl dict with model, scaler, feature_names, etc.
            raw_features: Feature dict from extract_response_features().

        Returns:
            ResponseMLVerdict for this model.
        """
        model = model_data['model']
        scaler = model_data['scaler']
        feature_names = model_data['feature_names']
        needs_scaling = model_data.get('needs_scaling', True)
        metrics = model_data.get('metrics', {})

        # Build DataFrame with correct column order from pkl
        feature_values = [raw_features.get(fname, 0) for fname in feature_names]
        df = pd.DataFrame([feature_values], columns=feature_names)

        # Scale if required (SVM models need scaling)
        if needs_scaling and scaler is not None:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                X = scaler.transform(df)
        else:
            X = df.values

        # Predict
        prediction = model.predict(X)[0]
        is_positive = bool(prediction == 1)

        # Get probability if model supports it
        confidence_pct = 50.0
        if hasattr(model, 'predict_proba'):
            try:
                probas = model.predict_proba(X)[0]
                # probas[1] = probability of positive class
                confidence_pct = float(probas[1]) * 100.0
            except Exception:
                pass
        elif hasattr(model, 'decision_function'):
            try:
                decision = model.decision_function(X)[0]
                # Map decision function to 0-100 via sigmoid
                sigmoid = 1.0 / (1.0 + np.exp(-decision))
                confidence_pct = float(sigmoid) * 100.0
            except Exception:
                pass

        # LOO accuracy from training metrics
        accuracy_loo = metrics.get('loo_accuracy', 0.5)

        return ResponseMLVerdict(
            model_name=model_name,
            prediction=is_positive,
            confidence_pct=round(confidence_pct, 1),
            label='positive' if is_positive else 'negative',
            accuracy_loo=round(accuracy_loo, 3),
        )
