#!/usr/bin/env python3
"""
Extract real SSRF cases (CVE-backed) from the projectdiscovery/nuclei-templates
corpus into the ML-SSRFinder dataset schema.

This is an INDEPENDENT source from the HackerOne reports already in
BALANCED_DATASET_40_EXAMPLES.json, so it supports the leave-one-source-out
validation requested by Reviewer 2 (comment R2-6).

Honest note on labels: a nuclei template encodes the real attack request
verbatim, plus the response SIGNATURE that confirms exploitation (status codes,
body words, header words, OOB interaction). It does not carry a captured
response body, so response_size_bytes / response_time_ms are null here.

Usage:
    git clone --depth 1 --filter=blob:none --sparse \
        https://github.com/projectdiscovery/nuclei-templates.git /tmp/nt
    cd /tmp/nt && git sparse-checkout set http
    python3 extract_nuclei_ssrf.py /tmp/nt out.json
"""

import glob
import json
import os
import re
import sys
from datetime import date
from urllib.parse import urlparse, parse_qsl, unquote

import yaml

SSRF_RE = re.compile(r"ssrf|server.side request forgery", re.I)

# Markers that identify the SSRF destination inside a payload.
TARGET_PATTERNS = [
    ("oob_collaborator", r"\{\{interactsh-url\}\}|oast\.(?:pro|live|site|fun|me|online)|interact\.sh|burpcollaborator"),
    ("cloud_metadata_aws", r"169\.254\.169\.254"),
    ("cloud_metadata_gcp", r"metadata\.google\.internal"),
    ("cloud_metadata_alibaba", r"100\.100\.100\.200"),
    # Includes obfuscated loopback: octal (0177.0.0.1), hex (0x7f...), decimal
    # (2130706433) and the bare "0" shorthand.
    ("localhost", r"127\.0\.0\.1|\blocalhost\b|\[::1\]|0\.0\.0\.0|0177\.0\.0\.1|0x7f[0-9a-f]{6}|(?<![\d.])2130706433(?![\d.])|(?<![\d.\w])0:\d+"),
    ("private_network", r"(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+"),
    ("link_local", r"169\.254\.(?!169\.254)\d+"),
    ("target_host_self", r"\{\{Hostname\}\}|\{\{BaseURL\}\}|\{\{Host\}\}"),
    ("local_file_scheme", r"\bfile:(?://|///)"),
    ("non_http_scheme", r"\b(?:gopher|dict|ftp|ldap|sftp|jar|netdoc|php)://"),
]

# (name, pattern, flags, scan_raw_request)
# scan_raw_request is only set for encoding tricks, whose evidence is destroyed
# by decoding. The rest are matched against the decoded payload alone, so that
# unrelated text elsewhere in the request cannot trigger them.
BYPASS_PATTERNS = [
    ("url_encoding", r"%2f|%3a|%2e", re.I, True),
    ("decimal_octal_ip", r"(?<![\d.])(?:2130706433|0177\.0|0x7f)", re.I, False),
    ("short_localhost_0", r"//0:\d+", 0, False),
    ("alternate_scheme", r"\b(?:file|gopher|dict|ftp|ldap|sftp|jar|netdoc)://", re.I, False),
    ("at_sign_confusion", r"//[^/\s]*@[\w.\-]+", 0, False),
    ("path_traversal_in_url", r"\.\./|\.\.%2f", re.I, True),
    ("redirect_chain", r"redirect|r=http|next=http|/cgi/redirect", re.I, False),
    ("dns_rebind", r"nip\.io|xip\.io|sslip\.io|rbndr", re.I, False),
]

PROTO_RE = re.compile(r"\b(https?|file|gopher|dict|ftp|ldap|sftp|jar|netdoc)://", re.I)
SCHEME_PREFIX_RE = re.compile(r"^(?:https?|file|gopher|dict|ftp|ldap|sftp|jar|netdoc)(?::|%3a)", re.I)


def is_ssrf_template(doc):
    """Keep only templates that are ABOUT SSRF.

    A plain full-text match pulls in unrelated templates (XSS, RCE) that merely
    mention SSRF in prose, so require the signal in the title, the tags, or the
    CWE classification.
    """
    info = doc.get("info", {}) or {}
    cls = info.get("classification", {}) or {}
    if "918" in str(cls.get("cwe-id") or ""):
        return True
    tags = info.get("tags") or ""
    if isinstance(tags, list):
        tags = ",".join(tags)
    if "ssrf" in tags.lower().split(",") or "ssrf" in [t.strip() for t in tags.lower().split(",")]:
        return True
    return bool(SSRF_RE.search(str(info.get("name") or "")))


def load_templates(root):
    """Yield (path, parsed_yaml) for every SSRF http template."""
    for path in sorted(glob.glob(os.path.join(root, "http", "**", "*.yaml"), recursive=True)):
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if not SSRF_RE.search(text):
            continue
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict) or not (doc.get("http") or doc.get("requests")):
            continue
        if not is_ssrf_template(doc):
            continue
        yield os.path.relpath(path, root), doc


def expand_payload_vars(text, payload_vars):
    """Substitute nuclei {{var}} placeholders with their first payload value.

    Templates park the attack string in a `payloads:` block and reference it
    as {{body}}, {{url}}, {{path}} and so on. The first value is representative
    of the attack; the rest are variants of the same technique.
    """
    if not text or not payload_vars:
        return text
    for name, values in payload_vars.items():
        if isinstance(values, str):
            first = values
        elif isinstance(values, (list, tuple)) and values:
            first = values[0]
        else:
            continue
        text = text.replace("{{%s}}" % name, str(first))
    return text


def parse_raw(raw):
    """Split a nuclei raw request into method, target, protocol, headers, body."""
    head, _, body = raw.partition("\n\n")
    lines = [ln for ln in head.splitlines() if ln.strip()]
    if not lines:
        return None
    parts = lines[0].split()
    method = parts[0] if parts else "GET"
    target = parts[1] if len(parts) > 1 else "/"
    protocol = parts[2] if len(parts) > 2 else "HTTP/1.1"
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip()] = v.strip()
    return {
        "method": method,
        "target": target,
        "protocol": protocol,
        "headers": headers,
        "body": body.strip() or None,
    }


def classify_target(payload):
    """Return (destination_category, is_internal, is_oob) for an SSRF payload."""
    for label, pattern in TARGET_PATTERNS:
        if re.search(pattern, payload, re.I):
            return label, label != "oob_collaborator", label == "oob_collaborator"
    return "external_or_unspecified", False, False


def detect_bypasses(payload, raw_request=""):
    """Detect filter-evasion techniques.

    The percent-encoding evidence only survives in the pre-decode text, so scan
    the raw request as well as the decoded payload.
    """
    found = []
    for name, pattern, flags, scan_raw in BYPASS_PATTERNS:
        target = payload + ("\n" + raw_request if scan_raw and raw_request else "")
        if re.search(pattern, target, flags):
            found.append(name)
    if re.search(r"%25[0-9a-f]{2}", raw_request, re.I):
        found.append("double_url_encoding")
    return found


def looks_like_ssrf_value(value):
    """Does this parameter value carry a URL / host the server would fetch?"""
    if not value:
        return False
    if PROTO_RE.search(value) or SCHEME_PREFIX_RE.match(value):
        return True
    for _, pattern in TARGET_PATTERNS:
        if re.search(pattern, value, re.I):
            return True
    return False


def deep_unquote(value, rounds=3):
    """Undo nested percent-encoding, which SSRF payloads use to dodge filters."""
    for _ in range(rounds):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


# A URL-ish token: scheme-prefixed, or a bare host/IP followed by a port or path.
URL_TOKEN_RE = re.compile(
    r"(?:(?:https?|file|gopher|dict|ftp|ldap|sftp|jar|netdoc|php)://[^\s\"'<>&\\]+"
    r"|\{\{interactsh-url\}\}[^\s\"'<>&\\]*)",
    re.I,
)


def find_injection(target, headers, body):
    """Locate the parameter carrying the SSRF payload.

    Returns (parameter_name, location, payload) or (None, None, None).
    Query and body values are percent-decoded before matching, because many
    payloads are double-encoded to bypass URL validation.
    """
    query = urlparse(target).query
    for name, value in parse_qsl(query, keep_blank_values=True):
        decoded = deep_unquote(value)
        if looks_like_ssrf_value(decoded):
            return name, "query", decoded

    if body:
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError):
            parsed = None
        if parsed is not None:
            hit = walk_json(parsed)
            if hit:
                return hit[0], "body", hit[1]

        ctype_is_xml = body.lstrip().startswith("<")
        if not ctype_is_xml:
            for name, value in parse_qsl(body, keep_blank_values=True):
                decoded = deep_unquote(value)
                if looks_like_ssrf_value(decoded):
                    return name, "body", decoded

        # multipart/form-data
        m = re.search(r'name="([^"]+)"[^\n]*\r?\n(?:[^\n]*\r?\n)*?\r?\n([^\r\n]+)', body)
        if m and looks_like_ssrf_value(m.group(2)):
            return m.group(1), "body", m.group(2).strip()

        # XML / SOAP: take the first URL-ish token and name it by its element.
        if ctype_is_xml:
            tok = URL_TOKEN_RE.search(body)
            if tok:
                before = body[: tok.start()]
                el = re.findall(r"<([\w:.\-]+)[^>]*>\s*$", before)
                attr = re.findall(r'([\w:.\-]+)\s*=\s*["\']$', before)
                name = attr[-1] if attr else (el[-1] if el else None)
                return name, "body", tok.group(0)

    for name, value in headers.items():
        if name.lower() in ("host", "content-type", "content-length", "user-agent", "accept"):
            continue
        if looks_like_ssrf_value(value):
            return name, "header", value

    # Payload folded into the path itself, often percent-encoded.
    path = deep_unquote(urlparse(target).path)
    if looks_like_ssrf_value(path):
        tok = URL_TOKEN_RE.search(path)
        return None, "path", tok.group(0) if tok else path

    # Last resort: scan the fully decoded request for any URL-ish token, and
    # recover the parameter name from a "name=<token>" neighbourhood.
    blob = deep_unquote(target + "\n" + (body or ""))
    tok = URL_TOKEN_RE.search(blob)
    if tok:
        m = re.search(r'([\w.\[\]\-]{1,40})\s*=\s*["\']?$', blob[: tok.start()])
        return (m.group(1) if m else None), "unresolved", tok.group(0)
    return None, None, None


def walk_json(obj, prefix=""):
    """Depth-first search for the first JSON field holding an SSRF-ish value."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, str) and looks_like_ssrf_value(v):
                return key, v
            hit = walk_json(v, key)
            if hit:
                return hit
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}[{i}]"
            if isinstance(v, str) and looks_like_ssrf_value(v):
                return key, v
            hit = walk_json(v, key)
            if hit:
                return hit
    return None


def summarize_matchers(entry):
    """Turn nuclei matchers into a response-evidence description."""
    out = {
        "expected_status": [],
        "body_words": [],
        "header_words": [],
        "content_type_words": [],
        "body_regex": [],
        "oob_protocols": [],
        "dsl": [],
        "matchers_condition": entry.get("matchers-condition", "or"),
    }
    for m in entry.get("matchers", []) or []:
        part = m.get("part", "body")
        mtype = m.get("type")
        words = m.get("words", []) or []
        regexes = m.get("regex", []) or []
        if mtype == "status":
            out["expected_status"].extend(m.get("status", []) or [])
        elif mtype == "dsl":
            out["dsl"].extend(m.get("dsl", []) or [])
        elif part.startswith("interactsh"):
            out["oob_protocols"].extend(words)
        elif part == "header":
            out["header_words"].extend(words)
        elif part == "content_type":
            out["content_type_words"].extend(words)
        elif mtype == "regex":
            out["body_regex"].extend(regexes)
        else:
            out["body_words"].extend(words)

    # dsl matchers encode the same evidence as an expression; unpack the common
    # forms so they are not lost.
    for expr in out["dsl"]:
        for status in re.findall(r"status_code\s*==\s*(\d{3})", expr):
            out["expected_status"].append(int(status))
        for w in re.findall(r"contains\s*\(\s*body\s*,\s*['\"](.+?)['\"]\s*\)", expr):
            out["body_words"].append(w)
        for w in re.findall(r"contains\s*\(\s*(?:all_)?headers?\s*,\s*['\"](.+?)['\"]\s*\)", expr):
            out["header_words"].append(w)
        if "interactsh_protocol" in expr:
            for w in re.findall(r"interactsh_protocol\s*==\s*['\"](\w+)['\"]", expr):
                out["oob_protocols"].append(w)

    out["expected_status"] = sorted(set(out["expected_status"]))
    return out


def content_type_from(evidence):
    for w in evidence["content_type_words"] + evidence["header_words"]:
        if "/" in w and not w.lower().startswith("http"):
            return w
    return None


def build_example(rel_path, doc, commit, index):
    info = doc.get("info", {}) or {}
    cls = info.get("classification", {}) or {}
    meta = info.get("metadata", {}) or {}
    entries = doc.get("http") or doc.get("requests") or []

    cve = cls.get("cve-id")
    cwe = str(cls.get("cwe-id") or "")
    tags = info.get("tags") or ""
    if isinstance(tags, list):
        tags = ",".join(tags)

    # Flatten every step of every request block, keeping the matchers that
    # belong to each block.
    steps = []
    for entry in entries:
        evidence = summarize_matchers(entry)
        # A `payloads:` block holds the attack strings that {{var}} placeholders
        # in the request expand to. Without substituting them the request looks
        # like it carries no payload at all.
        payload_vars = entry.get("payloads") or {}
        raws = [expand_payload_vars(r, payload_vars) for r in (entry.get("raw") or [])]
        if raws:
            reqs = [r for r in (parse_raw(raw) for raw in raws) if r]
        else:
            headers = dict(entry.get("headers") or {})
            body = expand_payload_vars(entry.get("body") or "", payload_vars) or None
            reqs = [{
                "method": entry.get("method", "GET"),
                "target": expand_payload_vars(p, payload_vars)
                          .replace("{{BaseURL}}", "").replace("{{RootURL}}", "") or "/",
                "protocol": "HTTP/1.1",
                "headers": headers,
                "body": body,
            } for p in (entry.get("path") or [])]
        for req in reqs:
            param, location, payload = find_injection(req["target"], req["headers"], req["body"])
            steps.append({"req": req, "evidence": evidence, "param": param,
                          "location": location, "payload": payload})

    if not steps:
        return []

    # The labelled example is the step that actually carries the SSRF payload.
    # Everything before it (login, token fetch, nonce grab) becomes a
    # precondition, not a separate training example.
    exploit_idx = next((i for i, s in enumerate(steps) if s["payload"]), len(steps) - 1)
    exploit = steps[exploit_idx]
    preconditions = [{
        "method": s["req"]["method"],
        "path": s["req"]["target"],
        "body": s["req"]["body"],
    } for s in steps[:exploit_idx]]

    req = exploit["req"]
    evidence = exploit["evidence"]
    payload = exploit["payload"] or ""
    category, is_internal, is_oob = classify_target(payload)
    raw_request_text = req["target"] + "\n" + (req["body"] or "")
    bypasses = detect_bypasses(payload, raw_request_text)
    proto_m = PROTO_RE.search(payload)

    has_body_evidence = bool(evidence["body_words"] or evidence["body_regex"])
    blind = bool(evidence["oob_protocols"]) and not has_body_evidence
    if blind:
        ssrf_type = "blind_oob"
    elif has_body_evidence:
        ssrf_type = "full_read"
    elif evidence["header_words"] or evidence["content_type_words"]:
        ssrf_type = "blind_header"
    elif evidence["expected_status"]:
        ssrf_type = "blind_status"
    else:
        ssrf_type = "unspecified"

    eid_base = cve or doc.get("id") or os.path.splitext(os.path.basename(rel_path))[0]
    return [{
        "example_id": f"NUCLEI-{eid_base}-{index:03d}",
        "is_vulnerable": True,
        "data_source": "nuclei_templates_cve",
        "extraction_date": str(date.today()),
        "http_request": {
            "method": req["method"],
            "path": req["target"],
            "protocol": req["protocol"],
            "headers": req["headers"] or None,
            "body": {
                "raw": req["body"],
                "content_type": (req["headers"] or {}).get("Content-Type"),
            } if req["body"] else None,
            "injection_details": {
                "vulnerable_parameter": exploit["param"],
                "parameter_location": exploit["location"],
                "requires_authentication": bool(
                    (req["headers"] or {}).get("Cookie")
                    or (req["headers"] or {}).get("Authorization")
                    or preconditions
                ),
                "requires_specific_headers": exploit["location"] == "header",
                # False when the payload is base64/XXE/multipart encoded in a
                # way this extractor cannot unwrap. Filter on it before
                # training on payload-derived features.
                "injection_resolved": bool(payload),
            },
            "precondition_requests": preconditions or None,
            "multi_step": bool(preconditions),
        },
        "payload": {
            "raw_payload": payload or None,
            "payload_classification": {
                "destination_category": category,
                "protocol": proto_m.group(1).lower() if proto_m else None,
                "is_internal": is_internal,
                "is_oob": is_oob,
            },
            "bypass_techniques": bypasses or ["none_required"],
        },
        "http_response": {
            "capture_type": "matcher_signature",
            "status_code": evidence["expected_status"][0] if evidence["expected_status"] else None,
            "expected_status_codes": evidence["expected_status"] or None,
            "response_size_bytes": None,
            "response_time_ms": None,
            "content_type": content_type_from(evidence),
            "body_evidence_words": evidence["body_words"] or None,
            "body_evidence_regex": evidence["body_regex"] or None,
            "header_evidence_words": evidence["header_words"] or None,
            "oob_evidence_protocols": evidence["oob_protocols"] or None,
            "dsl_expressions": evidence["dsl"] or None,
            "matchers_condition": evidence["matchers_condition"],
        },
        "vulnerability": {
            "ssrf_type": ssrf_type,
            "blind_ssrf": blind,
            "severity": info.get("severity"),
            "cvss_score": cls.get("cvss-score"),
            "cvss_metrics": cls.get("cvss-metrics"),
            "cwe_id": cwe or None,
            "is_cwe_918": "918" in cwe,
            "epss_score": cls.get("epss-score"),
        },
        "indicators": {
            "contains_cloud_metadata": category.startswith("cloud_metadata"),
            "contains_private_ip": category in ("private_network", "localhost", "link_local"),
            "requires_oob": is_oob,
            "kev_listed": "kev" in tags,
        },
        "affected_application": {
            "name": info.get("name"),
            "vendor": meta.get("vendor"),
            "product": meta.get("product"),
        },
        "source": {
            "type": "nuclei_template",
            "cve_id": cve,
            "template_id": doc.get("id"),
            "template_path": rel_path,
            "template_repo": "https://github.com/projectdiscovery/nuclei-templates",
            "template_commit": commit,
            "author": info.get("author"),
            "references": info.get("reference") or [],
            "title": info.get("name"),
        },
        "notes": (info.get("description") or "").strip() or None,
    }]


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "/tmp/nt"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "SSRF_CVE_DATASET_NUCLEI.json"
    commit = os.popen(f"git -C {root} rev-parse HEAD").read().strip() or None

    examples = []
    templates = 0
    for index, (rel_path, doc) in enumerate(load_templates(root), start=1):
        templates += 1
        examples.extend(build_example(rel_path, doc, commit, index))

    cwe918 = sum(1 for e in examples if e["vulnerability"]["is_cwe_918"])
    with_cve = sum(1 for e in examples if e["source"]["cve_id"])
    by_type = {}
    by_target = {}
    for e in examples:
        by_type[e["vulnerability"]["ssrf_type"]] = by_type.get(e["vulnerability"]["ssrf_type"], 0) + 1
        cat = e["payload"]["payload_classification"]["destination_category"]
        by_target[cat] = by_target.get(cat, 0) + 1

    dataset = {
        "dataset_info": {
            "version": "1.0",
            "name": "ssrf_cve_dataset_nuclei",
            "creation_date": str(date.today()),
            "source": "projectdiscovery/nuclei-templates",
            "source_commit": commit,
            "license": "MIT (templates); see upstream repository",
            "templates_processed": templates,
            "total_examples": len(examples),
            "vulnerable_count": len(examples),
            "benign_count": 0,
            "cve_backed_count": with_cve,
            "cwe_918_count": cwe918,
            "notes": (
                "Independent, non-HackerOne source of real SSRF cases for "
                "leave-one-source-out validation. Requests are verbatim attack "
                "requests; responses are matcher signatures (status codes, body "
                "words, header words, OOB protocol), not captured bodies, so "
                "response_size_bytes and response_time_ms are null."
            ),
        },
        "statistics": {
            "ssrf_types": by_type,
            "destination_categories": by_target,
        },
        "examples": examples,
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(dataset, fh, indent=2, ensure_ascii=False)
    print(f"templates: {templates}  examples: {len(examples)}  cve-backed: {with_cve}  cwe918: {cwe918}")
    print("ssrf_types:", by_type)
    print("targets:", by_target)
    print("written:", out_path)


if __name__ == "__main__":
    main()
