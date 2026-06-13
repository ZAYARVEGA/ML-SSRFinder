#!/usr/bin/env python3
"""
Neural Forger - SSRF Vulnerability Detector

Zero-dependency machine learning detector for Server-Side Request Forgery
vulnerabilities. Analyzes HTTP request structure without performing injection
to produce a vulnerability probability score.

This module is derived from the SSRF detector research dataset (40 examples)
and encodes learned feature weights as constants for fast, offline inference.

Public API:
    detect_ssrf(url, param_name, method, requires_auth) -> bool
    analyze_request(request_dict) -> dict
    get_recommended_payloads(url, param_name) -> list[dict]
"""

from typing import Dict, List, Any, Tuple, Optional

# ============================================================================
# Model constants (weights learned from 40-example training dataset)
# ============================================================================

FEATURE_WEIGHTS: Dict[str, float] = {
    "param_url":          0.30,   # parameter name contains 'url'
    "endpoint_api":       0.15,   # endpoint path contains '/api/'
    "param_webhook":      0.12,   # parameter name contains 'webhook' / 'hook'
    "requires_auth":     -0.11,   # authentication present (reduces risk)
    "endpoint_fetch":     0.10,   # endpoint path contains fetch/download/import
    "endpoint_webhook":   0.08,   # endpoint path contains webhook/hook
    "is_https":          -0.06,   # HTTPS endpoint (slightly reduces risk)
    "method_post":        0.05,   # POST method (slightly increases risk)
    "param_redirect":     0.09,   # parameter name contains 'redirect' / 'redir'
    "param_callback":     0.08,   # parameter name contains 'callback' / 'cb'
    "param_dest":         0.07,   # parameter name contains 'dest' / 'target' / 'path'
    "param_file":         0.06,   # parameter name contains 'file' / 'load' / 'src'
    "endpoint_proxy":     0.10,   # endpoint path contains 'proxy'
    "has_query_params":   0.03,   # URL contains query parameters
}

DECISION_THRESHOLD: float = 0.5
BASELINE_SCORE: float = 0.5

# Payload database ordered by dataset success rate
PAYLOAD_DATABASE: Dict[str, Dict[str, Any]] = {
    "localhost": {
        "success_rate": 37,
        "priority": "HIGH",
        "payloads": [
            "http://localhost/admin",
            "http://127.0.0.1/admin",
            "http://localhost:8080/admin",
            "http://0.0.0.0/admin",
            "http://[::1]/admin",
        ],
    },
    "aws_metadata": {
        "success_rate": 27,
        "priority": "CRITICAL",
        "payloads": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
        ],
    },
    "private_network": {
        "success_rate": 7,
        "priority": "MEDIUM",
        "payloads": [
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
        ],
    },
    "gcp_metadata": {
        "success_rate": 3,
        "priority": "CRITICAL",
        "payloads": [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        ],
    },
    "azure_metadata": {
        "success_rate": 2,
        "priority": "CRITICAL",
        "payloads": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        ],
    },
}


# ============================================================================
# Feature extraction
# ============================================================================

def extract_features(
    url: str,
    param_name: str = "",
    method: str = "GET",
    requires_auth: bool = False,
) -> Dict[str, bool]:
    """
    Extract boolean feature vector from HTTP request attributes.

    Args:
        url: Target endpoint URL.
        param_name: Name of the parameter under test.
        method: HTTP method.
        requires_auth: Whether the request requires authentication.

    Returns:
        Dictionary mapping feature names to boolean values.
    """
    url_lower = url.lower()
    param_lower = param_name.lower()

    return {
        "param_url":        "url" in param_lower,
        "param_webhook":    any(tok in param_lower for tok in ("webhook", "hook")),
        "param_redirect":   any(tok in param_lower for tok in ("redirect", "redir", "return", "next")),
        "param_callback":   any(tok in param_lower for tok in ("callback", "cb")),
        "param_dest":       any(tok in param_lower for tok in ("dest", "target", "path", "uri")),
        "param_file":       any(tok in param_lower for tok in ("file", "load", "src", "img", "image")),
        "endpoint_api":     "/api/" in url_lower,
        "endpoint_fetch":   any(tok in url_lower for tok in ("fetch", "download", "import")),
        "endpoint_webhook": any(tok in url_lower for tok in ("webhook", "hook")),
        "endpoint_proxy":   "proxy" in url_lower,
        "is_https":         url_lower.startswith("https://"),
        "requires_auth":    requires_auth,
        "method_post":      method.upper() == "POST",
        "has_query_params": "?" in url,
    }


# ============================================================================
# Scoring
# ============================================================================

def calculate_score(features: Dict[str, bool]) -> Tuple[bool, int]:
    """
    Compute vulnerability score from feature vector.

    Args:
        features: Boolean feature dictionary from extract_features().

    Returns:
        Tuple of (is_vulnerable, confidence_percentage).
        confidence_percentage is an integer 0-100.
    """
    score = BASELINE_SCORE

    for feature_name, weight in FEATURE_WEIGHTS.items():
        if features.get(feature_name, False):
            score += weight

    # Simplified sigmoid mapping to percentage
    if score > DECISION_THRESHOLD:
        confidence = min(95, 50 + (score - DECISION_THRESHOLD) * 100)
    else:
        confidence = max(5, 50 - (DECISION_THRESHOLD - score) * 100)

    is_vulnerable = score > DECISION_THRESHOLD
    return is_vulnerable, int(confidence)


def _determine_risk_level(is_vulnerable: bool, confidence: int) -> str:
    """
    Map vulnerability status and confidence to a risk level string.

    Args:
        is_vulnerable: Whether the model predicts vulnerability.
        confidence: Confidence percentage (0-100).

    Returns:
        Risk level string: CRITICAL, HIGH, MEDIUM, LOW, or SAFE.
    """
    if not is_vulnerable:
        return "SAFE"
    if confidence >= 90:
        return "CRITICAL"
    if confidence >= 70:
        return "HIGH"
    if confidence >= 50:
        return "MEDIUM"
    return "LOW"


# ============================================================================
# Public API
# ============================================================================

def detect_ssrf(
    url: str,
    param_name: str = "",
    method: str = "GET",
    requires_auth: bool = False,
) -> bool:
    """
    Quick boolean check for SSRF vulnerability.

    Args:
        url: Target endpoint URL.
        param_name: Name of the parameter under test.
        method: HTTP method.
        requires_auth: Whether the request requires authentication.

    Returns:
        True if the request structure suggests SSRF vulnerability.
    """
    features = extract_features(url, param_name, method, requires_auth)
    is_vulnerable, _ = calculate_score(features)
    return is_vulnerable


def analyze_request(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Full vulnerability analysis of an HTTP request.

    Args:
        request: Dictionary with keys:
            - url (str): Target endpoint URL.
            - method (str): HTTP method (default 'GET').
            - parameter_name (str): Parameter under test.
            - requires_auth (bool): Authentication required (default False).

    Returns:
        Dictionary containing:
            - vulnerable (bool)
            - confidence (int, 0-100)
            - risk_level (str)
            - endpoint (str)
            - parameter (str)
            - features_detected (list[str])
            - feature_details (list[dict]) with name, weight, description
            - recommended_payloads (list[dict])
    """
    url = request.get("url", "")
    param = request.get("parameter_name", "")
    method = request.get("method", "GET")
    auth = request.get("requires_auth", False)

    features = extract_features(url, param, method, auth)
    is_vulnerable, confidence = calculate_score(features)
    risk_level = _determine_risk_level(is_vulnerable, confidence)

    active_features = [name for name, active in features.items() if active]

    # Build detailed feature info
    feature_details = []
    for name in active_features:
        weight = FEATURE_WEIGHTS.get(name, 0.0)
        feature_details.append({
            "name": name,
            "weight": weight,
            "contribution": "positive" if weight > 0 else "negative",
            "description": _feature_description(name),
        })
    feature_details.sort(key=lambda fd: abs(fd["weight"]), reverse=True)

    payloads = get_recommended_payloads(url, param) if is_vulnerable else []

    return {
        "vulnerable": is_vulnerable,
        "confidence": confidence,
        "risk_level": risk_level,
        "endpoint": url,
        "parameter": param,
        "features_detected": active_features,
        "feature_details": feature_details,
        "recommended_payloads": payloads,
    }


def get_recommended_payloads(
    url: str = "",
    param_name: str = "",
) -> List[Dict[str, Any]]:
    """
    Return payload recommendations ordered by dataset success rate.

    Args:
        url: Target endpoint URL (used for context-aware recommendations).
        param_name: Parameter name (used for context-aware recommendations).

    Returns:
        List of payload recommendation dictionaries, each containing:
            - category (str)
            - priority (str)
            - success_rate (int)
            - payload (str)
            - alternatives (list[str])
    """
    url_lower = url.lower()
    param_lower = param_name.lower()

    recommendations: List[Dict[str, Any]] = []

    sorted_categories = sorted(
        PAYLOAD_DATABASE.items(),
        key=lambda item: item[1]["success_rate"],
        reverse=True,
    )

    for category, data in sorted_categories:
        recommendations.append({
            "category": category,
            "priority": data["priority"],
            "success_rate": data["success_rate"],
            "payload": data["payloads"][0],
            "alternatives": data["payloads"][1:],
        })

    # Context-aware extras
    if any(tok in url_lower for tok in ("fetch", "proxy", "download")):
        recommendations.append({
            "category": "port_scan",
            "priority": "MEDIUM",
            "success_rate": 0,
            "payload": "http://localhost:22",
            "alternatives": [
                "http://localhost:3306",
                "http://localhost:6379",
                "http://localhost:5432",
            ],
        })

    if any(tok in param_lower for tok in ("webhook", "callback", "notify")):
        recommendations.append({
            "category": "oob_detection",
            "priority": "LOW",
            "success_rate": 0,
            "payload": "http://burpcollaborator.net",
            "alternatives": [
                "http://webhook.site/unique-id",
                "http://pingb.in/unique-id",
            ],
        })

    return recommendations


# ============================================================================
# Internal helpers
# ============================================================================

_FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "param_url":        "Parameter name contains 'url' (primary SSRF indicator)",
    "param_webhook":    "Parameter name contains 'webhook' or 'hook'",
    "param_redirect":   "Parameter name indicates redirect target",
    "param_callback":   "Parameter name indicates callback URL",
    "param_dest":       "Parameter name indicates destination/target/path",
    "param_file":       "Parameter name indicates file load or source",
    "endpoint_api":     "Endpoint path contains '/api/'",
    "endpoint_fetch":   "Endpoint handles fetch/download/import operations",
    "endpoint_webhook": "Endpoint processes webhooks",
    "endpoint_proxy":   "Endpoint acts as a proxy",
    "is_https":         "HTTPS transport (slightly reduces risk surface)",
    "requires_auth":    "Authentication required (reduces exploitation surface)",
    "method_post":      "POST method (may indicate data submission vector)",
    "has_query_params": "URL contains query parameters",
}


def _feature_description(name: str) -> str:
    """Return human-readable description for a feature name."""
    return _FEATURE_DESCRIPTIONS.get(name, name)
