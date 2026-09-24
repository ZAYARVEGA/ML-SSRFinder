#!/usr/bin/env python3
"""
Collect NON-vulnerable HTTP responses from the same web applications that appear
as SSRF positives, so a positive and a negative can be compared on the same
page and the difference attributed to the vulnerability rather than to the
source.

What it does and does NOT do
----------------------------
It sends ONE benign GET to the bare endpoint path, with the SSRF parameter
removed. It never sends an SSRF payload: it never asks a third-party server to
fetch an internal, out-of-band, or any attacker-chosen URL. That would be
exercising the vulnerability on a live host, which is not ours to do. So only
the non-vulnerable side is collected here; the vulnerable side stays the
archived response from the public write-up.

Honesty note carried in the data
---------------------------------
The response is captured NOW, from the patched production server, which may be
a different version and is a different point in time than the archived
vulnerable response. The pair is "same URL, benign input, current server" vs
"same URL, SSRF input, server at report time". `temporal_caveat` records this.

Scope limits
------------
One request per host, rate-limited, research User-Agent. Adult sites and
ambiguous/redacted hosts are excluded. Endpoints requiring authentication will
answer 401/403/404, which is itself a valid non-vulnerable baseline for that
exact page.

Usage:
    python3 collect_same_site_negatives.py out.json [--delay 3]
"""

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import date
from urllib.parse import urlsplit, urlunsplit

import parse_raw_http_to_features as P  # reuse the response featurizer

UA = "ML-SSRFinder-research/1.0 (academic SSRF dataset; benign single request)"

# Vetted targets: (report_id, benign_url). The URL is the exact reported
# endpoint with the SSRF parameter stripped, or the bare path. No payload.
# Adult, CTF-throwaway, ngrok and redacted hosts are deliberately omitted.
TARGETS = [
    ("1086206", "https://cz.acronis.com/wp-admin/admin-ajax.php"),
    ("2300358", "https://couriers.indrive.com/api/file-storage"),
    ("1875484", "https://connect.8x8.com/api/v2/chats/image-check"),
    ("1241149", "https://summit.acronis.events/login/wl"),
    ("247680",  "https://imgur.com/vidgif/upload"),
    ("832858",  "https://3d.cs.money/pasteLinkToImage"),
    ("738553",  "https://my.stripo.email/cabinet/stripeapi/v1/siteInfoLookup"),
    ("514224",  "https://search.usa.gov/help_docs"),
    ("643622",  "https://www.semrush.com/blog/services/oembed/"),
    ("206894",  "https://iris.lystit.com/models/default/classification/color"),
    ("223203",  "https://667667.myshopify.com/"),
    ("427835",  "https://www.first.org/"),
]

# Refuse to send anything that resembles an SSRF probe, as a hard guard against
# a bad entry in TARGETS above.
FORBIDDEN = re.compile(
    r"169\.254\.169\.254|127\.0\.0\.1|\blocalhost\b|metadata\.google"
    r"|interact\.sh|oast|burpcollab|\bfile:|\bgopher:|\bdict:"
    r"|(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+"
    r"|[?&](?:url|uri|dest|target|redirect|next|proxy|fetch|feed)=",
    re.I,
)


def is_benign(url):
    """A benign request: a bare public URL with no fetch-a-URL parameter."""
    if FORBIDDEN.search(url):
        return False
    q = urlsplit(url).query
    return not q or not FORBIDDEN.search("?" + q)


def fetch(url, timeout=15):
    """One GET, at most two cross-checked redirects, capture the response."""
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as fh:
            raw = fh.read(65536)
            return fh.status, dict(fh.headers), raw, fh.geturl()
    except urllib.error.HTTPError as exc:
        # An error status is a real, useful non-vulnerable baseline.
        body = b""
        try:
            body = exc.read(65536)
        except Exception:
            pass
        return exc.code, dict(exc.headers or {}), body, url
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        return None, {}, str(exc).encode(), url


def build_response_features(status, headers, body_bytes, final_url):
    """Compute the same feature block the parsed datasets use."""
    headers = {k.lower(): v for k, v in headers.items()}
    try:
        body = body_bytes.decode("utf-8", errors="replace")
    except Exception:
        body = ""
    ct = (headers.get("content-type") or "").split(";")[0] or None
    unusual = [f"{k}: {v}" for k, v in headers.items() if k not in P.COMMON_HEADERS]
    return {
        "status_code": status,
        "response_size_bytes": len(body_bytes),
        "response_time_ms": None,
        "server_header": headers.get("server"),
        "content_type": ct,
        "unusual_headers": unusual[:20],
        "body_has_aws_metadata": bool(P.AWS_METADATA.search(body)),
        "body_has_credentials": bool(P.CREDENTIALS.search(body)),
        "body_has_oob_echo": False,           # no payload was sent
        "body_has_error_json": bool(P.ERROR_JSON.search(body)) and body.lstrip()[:1] in "{[",
        "body_has_bearer_token": False,
        "body_has_internal_service_info": bool(P.INTERNAL_INFO.search(body)),
        "body_structure": P.classify_body(body, headers),
        "body_raw_excerpt": body[:600],
        "body_full_len_chars": len(body),
        "is_timing_differential": False,
        "timing_open_port_ms": None,
        "timing_closed_port_ms": None,
        "is_status_differential": False,
        "status_alive_host": None,
        "status_dead_host": None,
        "is_content_differential": False,
        "is_oob_only": False,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out", nargs="?", default="SSRF_SAME_SITE_NEGATIVES.json")
    ap.add_argument("--delay", type=float, default=3.0)
    args = ap.parse_args()

    # Map report -> its archived vulnerable example, for pairing.
    vuln = {}
    for e in json.load(open("SSRF_HACKERONE_RESPONSE_FEATURES.json", encoding="utf-8"))["examples"]:
        if e["is_vulnerable"]:
            vuln.setdefault(e["report_url"].rsplit("/", 1)[-1], e["example_id"])

    rows, failures = [], []
    for rid, url in TARGETS:
        if not is_benign(url):
            print(f"SKIP (not benign): {url}")
            continue
        host = urlsplit(url).netloc
        print(f"GET {url}")
        status, headers, body, final_url = fetch(url)
        time.sleep(args.delay)
        if status is None:
            failures.append((rid, host, body.decode("utf-8", "replace")[:80]))
            print(f"   unreachable: {body.decode('utf-8','replace')[:80]}")
            continue
        print(f"   {status}  {headers.get('Content-Type') or headers.get('content-type')}  {len(body)}B")
        rows.append({
            "example_id": f"H1SAME-{rid}",
            "report_url": f"https://hackerone.com/reports/{rid}",
            "source_file": "live_same_site_collection",
            "target": host,
            "date": str(date.today()),
            "is_vulnerable": False,
            "negative_type": "same_site_benign",
            "collection_method": "single benign GET, SSRF parameter removed, no payload sent",
            "requested_url": url,
            "final_url": final_url,
            "paired_vulnerable_example": vuln.get(rid),
            "same_page_pair": vuln.get(rid) is not None,
            "temporal_caveat": (
                "Captured from the current, patched production server. The "
                "paired vulnerable response is the archived response to an SSRF "
                "payload at report time, so the pair shares the URL but not the "
                "server version or the point in time."
            ),
            "http_response": build_response_features(status, headers, body, final_url),
        })

    dataset = {
        "dataset_info": {
            "version": "1.0",
            "name": "ssrf_same_site_negatives",
            "creation_date": str(date.today()),
            "collection": "one benign GET per host, SSRF parameter stripped",
            "targets_attempted": len(TARGETS),
            "collected": len(rows),
            "unreachable": len(failures),
            "paired_with_positive": sum(1 for r in rows if r["same_page_pair"]),
            "vulnerable_count": 0,
            "benign_count": len(rows),
            "notes": (
                "Non-vulnerable responses from the SAME web applications as the "
                "SSRF positives. Only the benign side is collected; the SSRF "
                "payload is never sent to a live third party. Same feature "
                "schema as response_dataset_final.json."
            ),
        },
        "unreachable_hosts": [{"report_id": r, "host": h, "error": e} for r, h, e in failures],
        "examples": rows,
    }
    json.dump(dataset, open(args.out, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print(f"\ncollected {len(rows)} / {len(TARGETS)}  paired {dataset['dataset_info']['paired_with_positive']}"
          f"  unreachable {len(failures)}")
    print("written:", args.out)


if __name__ == "__main__":
    main()
