#!/usr/bin/env python3
"""
Turn the raw HTTP request/response blocks harvested from public SSRF write-ups
into rows that match the feature schema of response_dataset_final.json.

Input:  SSRF_HACKERONE_RAW_HTTP.json (produced by harvest_hackerone_ssrf.py)
Output: a dataset with the same feature_schema as response_dataset_final.json,
        so the rows can be concatenated with the existing training data.

Every feature is derived from the captured text. Features that cannot be
derived from a static write-up (response_time_ms, the timing differentials) are
left null rather than guessed, and rows keep a `needs_manual_review` flag so
curation effort can be aimed at the ambiguous ones.

Usage:
    python3 parse_raw_http_to_features.py SSRF_HACKERONE_RAW_HTTP.json out.json
"""

import json
import re
import sys
from datetime import date

REQ_LINE = re.compile(
    r"^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)\s+HTTP/(\d(?:\.\d)?)\s*$",
    re.M,
)
RESP_LINE = re.compile(r"^\s*HTTP/(\d(?:\.\d)?)\s+(\d{3})(?:\s+(.*))?$", re.M)

COMMON_HEADERS = {
    "date", "content-type", "content-length", "connection", "server",
    "cache-control", "vary", "content-encoding", "transfer-encoding",
    "keep-alive", "expires", "pragma", "set-cookie", "location", "etag",
}

# Distinctive IMDS tokens only. Weak standalone words (security-groups,
# instance-type, local-ipv4, public-keys) also appear in benign AWS-SDK
# JavaScript on ordinary sites, so they are excluded to avoid false positives.
AWS_METADATA = re.compile(
    r"\bami-id\b|\bami-launch-index\b|\bami-manifest-path\b"
    r"|block-device-mapping/|\bami-manifest\b|instance-action"
    r"|\breservation-id\b|iam/security-credentials",
    re.I,
)
CREDENTIALS = re.compile(
    r"AccessKeyId|SecretAccessKey|\"Token\"\s*:|aws_secret_access_key|SessionToken",
    re.I,
)
OOB_ECHO = re.compile(
    r"burpcollaborator\.net|oastify\.com|\.oast\.(?:pro|live|site|fun|me|online)"
    r"|interact\.sh|requestbin|pipedream\.net|\.ngrok\.io|canarytokens",
    re.I,
)
BEARER = re.compile(r"authorization\s*:\s*bearer\s+\S+", re.I)
ERROR_JSON = re.compile(
    r'"(?:error|errors|message|code)"\s*:|ValidationError|InvalidRequest|"success"\s*:\s*false',
    re.I,
)
# Real internal-service disclosure: private IPs, internal hostnames, and named
# backend services. Generic HTML tags (<title>, <html>) were removed because
# they fire on every web page and are not evidence of an internal service.
INTERNAL_INFO = re.compile(
    r'\bkubernetes\b|\bconsul\b|\belasticsearch\b|\bredis\b|\bjenkins\b'
    r'|\bmongodb\b|\bmemcached\b|\bzookeeper\b|\bkibana\b|\bgrafana\b'
    r'|X-Powered-By\s*:|Server\s*:\s*(?:jetty|gunicorn|werkzeug|thin)'
    r'|(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+'
    r'|\b127\.0\.0\.1\b|\.internal\b|\.svc\.cluster\.local',
    re.I,
)
PRIVATE_TARGET = re.compile(
    r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200"
    r"|127\.0\.0\.1|\blocalhost\b|\[::1\]|0\.0\.0\.0"
    r"|(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+",
    re.I,
)


def split_message(block):
    """Split an HTTP message into (start_line, headers dict, body)."""
    text = block.replace("\r\n", "\n").strip("\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    start = lines[0] if lines else ""
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            k = k.strip()
            if k and " " not in k:
                headers[k.lower()] = v.strip()
    return start, headers, body


def classify_body(body, headers):
    if not body.strip():
        return "empty"
    if AWS_METADATA.search(body) and not body.lstrip().startswith("{"):
        return "metadata_listing"
    if CREDENTIALS.search(body):
        return "credentials_json"
    stripped = body.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "error_json" if ERROR_JSON.search(body) else "success_json"
    if stripped.startswith("<?xml") or re.match(r"<(?:soap|envelope|\w+:Envelope)", stripped, re.I):
        return "xml_response"
    if "<html" in body.lower() or "<!doctype html" in body.lower():
        return "html_echo"
    ct = (headers.get("content-type") or "").lower()
    if "json" in ct:
        return "error_json" if ERROR_JSON.search(body) else "success_json"
    if "xml" in ct:
        return "xml_response"
    if "html" in ct:
        return "html_echo"
    return "text_plain"


def parse_response(block):
    start, headers, body = split_message(block)
    m = RESP_LINE.search(start) or RESP_LINE.search(block)
    status = int(m.group(2)) if m else None
    # If the status line was not the first line, re-split from there.
    if m and not RESP_LINE.search(start):
        idx = block.find(m.group(0))
        start, headers, body = split_message(block[idx:])
    unusual = [f"{k}: {v}" for k, v in headers.items() if k not in COMMON_HEADERS]
    return {
        "status_code": status,
        "response_size_bytes": len(body.encode("utf-8")) if body else 0,
        "response_time_ms": None,
        "server_header": headers.get("server"),
        "content_type": (headers.get("content-type") or "").split(";")[0] or None,
        "unusual_headers": unusual or [],
        "body_has_aws_metadata": bool(AWS_METADATA.search(body)),
        "body_has_credentials": bool(CREDENTIALS.search(body)),
        "body_has_oob_echo": bool(OOB_ECHO.search(body)),
        "body_has_error_json": bool(ERROR_JSON.search(body)) and classify_body(body, headers) in ("error_json",),
        "body_has_bearer_token": False,  # filled from the request side
        "body_has_internal_service_info": bool(INTERNAL_INFO.search(body)),
        "body_structure": classify_body(body, headers),
        "body_raw_excerpt": body[:600] if body else "",
        "is_timing_differential": False,
        "timing_open_port_ms": None,
        "timing_closed_port_ms": None,
        "is_status_differential": False,
        "status_alive_host": None,
        "status_dead_host": None,
        "is_content_differential": False,
        "is_oob_only": False,
    }


def parse_request(block):
    start, headers, body = split_message(block)
    m = REQ_LINE.search(start) or REQ_LINE.search(block)
    if not m:
        return None
    if not REQ_LINE.search(start):
        idx = block.find(m.group(0))
        start, headers, body = split_message(block[idx:])
        m = REQ_LINE.search(start) or m
    return {
        "method": m.group(1),
        "path": m.group(2),
        "http_version": m.group(3),
        "headers": headers,
        "body": body or None,
        "has_bearer_token": bool(BEARER.search(block)),
        "targets_internal_resource": bool(PRIVATE_TARGET.search(start + "\n" + body)),
    }


FENCE = re.compile(r"```[\w-]*\n(.*?)```", re.S)
TOKEN = re.compile(r"\b[a-z0-9]{16,}\b", re.I)


def indexed_blocks(report_body):
    """Return [(position, block_text)] for the write-up's code blocks.

    Position matters: a request and the response it produced are almost always
    written next to each other, so proximity is what pairs them. Pairing by
    list index instead (first request with first response) silently mismatches
    write-ups that show extra requests or several attempts.
    """
    blocks = [(m.start(), m.group(1).strip()) for m in FENCE.finditer(report_body)]
    return blocks if blocks else [(0, report_body)]


def pair_blocks(report_body):
    """Split blocks into requests and responses, keeping document order.

    A single block often holds a request AND the response beneath it; that case
    is kept as an explicit pair.
    """
    requests, responses, pairs = [], [], []
    for pos, block in indexed_blocks(report_body):
        req_m = REQ_LINE.search(block)
        resp_m = RESP_LINE.search(block)
        if req_m and resp_m and resp_m.start() > req_m.start():
            # Request and response in one block: split at the status line.
            requests.append((pos, block[: resp_m.start()]))
            responses.append((pos + 1, block[resp_m.start():]))
            pairs.append((block[: resp_m.start()], block[resp_m.start():]))
            continue
        if req_m:
            requests.append((pos, block))
        if resp_m:
            responses.append((pos, block))
    return requests, responses, pairs


def nearest_request(requests, resp_pos):
    """The closest request block appearing before this response."""
    before = [(pos, b) for pos, b in requests if pos <= resp_pos]
    if before:
        return max(before, key=lambda x: x[0])[1]
    return requests[0][1] if requests else None


def detect_oob_echo(body, request_block):
    """An OOB echo is a long random token that also appears in the request.

    Matching the collaborator DOMAIN alone misses the common case where the
    response contains only the random subdomain label echoed back.
    """
    if OOB_ECHO.search(body):
        return True
    if not request_block:
        return False
    req_tokens = set(t.lower() for t in TOKEN.findall(request_block))
    body_tokens = TOKEN.findall(body)
    if any(t.lower() in req_tokens for t in body_tokens):
        return True
    # The request points at a collaborator host and the body is the random
    # string that host serves back. The two tokens differ by design, so token
    # overlap alone would miss it.
    return bool(OOB_ECHO.search(request_block) and body_tokens)


def infer_ssrf_type(response, report):
    body = response["body_raw_excerpt"]
    text = (report.get("report_body") or "").lower()
    if response["body_has_credentials"] or response["body_has_aws_metadata"]:
        return "full_read"
    if response["body_has_oob_echo"] or "collaborator" in text or "interactsh" in text:
        return "blind_oob"
    if "time-based" in text or "response time" in text or "delay" in text:
        return "blind_timing"
    if body.strip():
        return "full_read"
    return "blind_status"


def severity_of(report):
    sev = (report.get("severity_rating") or "").lower()
    return sev if sev in ("critical", "high", "medium", "low") else None


def build_rows(harvest):
    rows = []
    for report in harvest.get("reports", []):
        body_text = report.get("report_body") or ""
        req_blocks, resp_blocks, _ = pair_blocks(body_text)
        if not resp_blocks:
            continue
        bearer = any(BEARER.search(b) for _, b in req_blocks)

        for i, (resp_pos, block) in enumerate(resp_blocks, start=1):
            resp = parse_response(block)
            if resp["status_code"] is None:
                continue
            req_block = nearest_request(req_blocks, resp_pos)
            matched = parse_request(req_block) if req_block else None
            resp["body_has_bearer_token"] = bearer
            resp["body_has_oob_echo"] = detect_oob_echo(resp["body_raw_excerpt"], req_block or "")
            resp["is_oob_only"] = resp["body_has_oob_echo"] and not resp["body_raw_excerpt"].strip()
            requests = [matched] if matched else []

            # A response block is only evidence of SSRF when the write-up is a
            # confirmed SSRF and the request actually pointed somewhere internal.
            confirmed = (
                report.get("is_cwe_ssrf")
                and report.get("substate") == "resolved"
                and report.get("ssrf_markers_present")
            )
            rows.append({
                "example_id": f"H1RAW-{report['report_id']}-R{i:03d}",
                "report_url": report["url"],
                "source_file": "hackerone_hacktivity_api",
                "target": report.get("team"),
                "date": (report.get("disclosed_at") or "")[:10] or None,
                "is_vulnerable": bool(confirmed),
                "ssrf_type": infer_ssrf_type(resp, report),
                "severity": severity_of(report),
                "matched_request": matched,
                "http_response": resp,
                "label_evidence": {
                    "hackerone_cwe": report.get("hacktivity_cwe"),
                    "substate": report.get("substate"),
                    "internal_target_in_request": any(
                        r["targets_internal_resource"] for r in requests
                    ),
                    "ssrf_markers_in_report": report.get("ssrf_markers_present"),
                },
                # Rows where the automatic signals disagree need a human pass
                # before they go into training.
                "needs_manual_review": bool(
                    confirmed
                    and not (resp["body_has_aws_metadata"] or resp["body_has_credentials"]
                             or resp["body_has_oob_echo"] or resp["body_has_internal_service_info"])
                ),
                "context": report.get("title"),
            })
    return rows


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "SSRF_HACKERONE_RAW_HTTP.json"
    out = sys.argv[2] if len(sys.argv) > 2 else "SSRF_HACKERONE_RESPONSE_FEATURES.json"
    harvest = json.load(open(src, encoding="utf-8"))
    rows = build_rows(harvest)

    ref = json.load(open("response_dataset_final.json", encoding="utf-8"))
    vuln = sum(1 for r in rows if r["is_vulnerable"])
    review = sum(1 for r in rows if r["needs_manual_review"])
    dataset = {
        "dataset_info": {
            "version": "1.0",
            "name": "ssrf_hackerone_raw_http_response_features",
            "creation_date": str(date.today()),
            "source": "HackerOne Hacktivity public disclosures (API harvest)",
            "reports_covered": len({r["report_url"] for r in rows}),
            "total_examples": len(rows),
            "vulnerable_count": vuln,
            "unconfirmed_count": len(rows) - vuln,
            "needs_manual_review": review,
            "notes": (
                "Auto-parsed from raw HTTP blocks in public write-ups. Same "
                "feature_schema as response_dataset_final.json. Timing features "
                "are null because static write-ups do not record them."
            ),
        },
        "feature_schema": ref["feature_schema"],
        "examples": rows,
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(dataset, fh, indent=2, ensure_ascii=False)
    print(f"rows: {len(rows)} | confirmed vulnerable: {vuln} | need review: {review}")
    print("written:", out)


if __name__ == "__main__":
    main()
