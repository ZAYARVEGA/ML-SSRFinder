#!/usr/bin/env python3
"""
Harvest publicly disclosed SSRF reports from HackerOne Hacktivity and keep the
ones that contain a raw HTTP request and/or a raw HTTP response in the report
body.

Only public, disclosed reports are touched, through the same endpoints the
public website uses. Nothing here needs authentication.

Output: a JSON file with, per report, the report metadata plus every raw HTTP
request/response block found in the write-up, so they can be curated into the
training set.

Usage:
    python3 harvest_hackerone_ssrf.py out.json [--max 400] [--delay 0.8]
"""

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request

GRAPHQL = "https://hackerone.com/graphql"
REPORT_JSON = "https://hackerone.com/reports/%s.json"
UA = "ML-SSRFinder-research/1.0 (academic SSRF dataset; contact via repo)"

SEARCH_QUERY = """
query HacktivitySearchQuery($queryString: String!, $from: Int, $size: Int, $sort: SortInput!) {
  search(index: CompleteHacktivityReportIndex, query_string: $queryString,
         from: $from, size: $size, sort: $sort) {
    total_count
    nodes {
      ... on HacktivityDocument {
        _id
        severity_rating
        disclosed_at
        submitted_at
        cwe
        cve_ids
        total_awarded_amount
        currency
        report { databaseId: _id title substate }
        team { handle }
        reporter { username }
      }
    }
  }
}
"""

# A request line: "POST /path?x=1 HTTP/1.1"
REQ_LINE = re.compile(
    r"^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)\s+HTTP/\d(?:\.\d)?\s*$",
    re.M,
)
# A status line: "HTTP/1.1 200 OK"
RESP_LINE = re.compile(r"^\s*HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s+.*)?$", re.M)
FENCE = re.compile(r"```[\w-]*\n(.*?)```", re.S)

SSRF_MARKERS = re.compile(
    r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200"
    r"|127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0"
    r"|(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+"
    r"|burpcollaborator|oastify|interact\.sh|\.oast\.|requestbin|ngrok"
    r"|\bfile://|\bgopher://|\bdict://",
    re.I,
)


def post_json(url, payload, retries=3):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": UA, "Accept": "application/json"},
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=40) as fh:
                return json.load(fh)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            if attempt == retries - 1:
                raise
            time.sleep(2 * (attempt + 1))
            print(f"  retry ({exc})", file=sys.stderr)
    return None


def get_json(url, retries=3):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=40) as fh:
                return json.load(fh)
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 403):
                return None
            if attempt == retries - 1:
                return None
            time.sleep(2 * (attempt + 1))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            if attempt == retries - 1:
                return None
            time.sleep(2 * (attempt + 1))
    return None


def search_reports(query, max_results, delay):
    """Page through Hacktivity search results."""
    out, offset, total = [], 0, None
    page = 100
    while len(out) < max_results:
        resp = post_json(GRAPHQL, {
            "operationName": "HacktivitySearchQuery",
            "query": SEARCH_QUERY,
            "variables": {
                "queryString": query,
                "from": offset,
                "size": page,
                "sort": {"field": "latest_disclosable_activity_at", "direction": "DESC"},
            },
        })
        search = ((resp or {}).get("data") or {}).get("search") or {}
        nodes = search.get("nodes") or []
        if total is None:
            total = search.get("total_count")
            print(f"hacktivity matches for {query!r}: {total}")
        if not nodes:
            break
        out.extend(nodes)
        offset += len(nodes)
        if total is not None and offset >= total:
            break
        time.sleep(delay)
    return out[:max_results]


def candidate_blocks(text):
    """Fenced code blocks first, then the raw text as a fallback."""
    blocks = [b.strip() for b in FENCE.findall(text)]
    return blocks if blocks else [text]


def extract_http(text):
    """Pull raw HTTP request and response blocks out of a report body."""
    requests, responses = [], []
    for block in candidate_blocks(text):
        has_req = REQ_LINE.search(block)
        has_resp = RESP_LINE.search(block)
        if has_req:
            requests.append(block)
        if has_resp:
            responses.append(block)
    return requests, responses


def report_text(report):
    parts = [report.get("vulnerability_information") or ""]
    for s in report.get("summaries") or []:
        parts.append(s.get("content") or "")
    return "\n\n".join(p for p in parts if p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out", nargs="?", default="SSRF_HACKERONE_RAW_HTTP.json")
    ap.add_argument("--query", default="ssrf")
    ap.add_argument("--max", type=int, default=400)
    ap.add_argument("--delay", type=float, default=0.8)
    args = ap.parse_args()

    nodes = search_reports(args.query, args.max, args.delay)
    print(f"fetched {len(nodes)} search hits; pulling report bodies")

    harvested, skipped = [], 0
    for i, node in enumerate(nodes, start=1):
        rid = (node.get("report") or {}).get("databaseId") or node.get("_id")
        if not rid:
            continue
        data = get_json(REPORT_JSON % rid)
        time.sleep(args.delay)
        if not data:
            skipped += 1
            continue
        text = report_text(data)
        if not text:
            skipped += 1
            continue
        requests, responses = extract_http(text)
        title = data.get("title") or ""
        if not requests and not responses:
            continue

        harvested.append({
            "report_id": rid,
            "url": f"https://hackerone.com/reports/{rid}",
            "title": title,
            "team": (data.get("team") or {}).get("handle"),
            "reporter": (data.get("reporter") or {}).get("username"),
            "severity_rating": data.get("severity_rating") or node.get("severity_rating"),
            "substate": data.get("substate"),
            "weakness": (data.get("weakness") or {}).get("name") or node.get("cwe"),
            # HackerOne's own CWE label. Use this, not the title, to decide
            # whether a report is a true SSRF positive.
            "hacktivity_cwe": node.get("cwe"),
            "is_cwe_ssrf": "server-side request forgery" in (node.get("cwe") or "").lower(),
            "bounty_amount": node.get("total_awarded_amount"),
            "bounty_currency": node.get("currency"),
            "cve_ids": data.get("cve_ids") or node.get("cve_ids") or [],
            "disclosed_at": data.get("disclosed_at"),
            "submitted_at": data.get("submitted_at"),
            "has_raw_request": bool(requests),
            "has_raw_response": bool(responses),
            "has_request_and_response": bool(requests and responses),
            "ssrf_markers_present": bool(SSRF_MARKERS.search(text)),
            "raw_http_requests": requests,
            "raw_http_responses": responses,
            "report_body": text,
        })
        if i % 25 == 0:
            print(f"  {i}/{len(nodes)} processed, {len(harvested)} with raw HTTP")

    both = sum(1 for h in harvested if h["has_request_and_response"])
    marked = sum(1 for h in harvested if h["ssrf_markers_present"])
    cwe_ssrf = sum(1 for h in harvested if h["is_cwe_ssrf"])
    gold = sum(1 for h in harvested
               if h["has_request_and_response"] and h["is_cwe_ssrf"] and h["ssrf_markers_present"])
    payload = {
        "dataset_info": {
            "name": "ssrf_hackerone_raw_http",
            "source": "HackerOne Hacktivity, publicly disclosed reports only",
            "query": args.query,
            "search_hits": len(nodes),
            "reports_with_raw_http": len(harvested),
            "reports_with_request_and_response": both,
            "reports_with_ssrf_markers": marked,
            "reports_labelled_cwe_918_by_hackerone": cwe_ssrf,
            "gold_candidates": gold,
            "skipped_unfetchable": skipped,
            "notes": (
                "Raw blocks are copied verbatim from the public write-ups. "
                "Titles matched the query 'ssrf'; confirm each report is truly "
                "SSRF before labelling, since full-text search also returns "
                "reports that merely mention SSRF."
            ),
        },
        "reports": harvested,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    print(f"\nwith raw HTTP: {len(harvested)} | request+response: {both} | "
          f"ssrf markers: {marked} | cwe-918: {cwe_ssrf} | gold: {gold}")
    print("written:", args.out)


if __name__ == "__main__":
    main()
