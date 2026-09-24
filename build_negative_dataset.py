#!/usr/bin/env python3
"""
Build the non-vulnerable (negative) class for ML-SSRFinder.

The positives are real SSRF cases (SSRF_CVE_DATASET_NUCLEI.json,
SSRF_HACKERONE_RESPONSE_FEATURES.json). A negative class drawn from a different
kind of source would let the model separate the classes by source artefacts
rather than by the vulnerability, which is exactly Reviewer 2's complaint
(R2-6). So the negatives here are drawn, wherever possible, from the SAME
corpus and the same extraction pipeline as the positives.

Five strata, each tagged with `negative_type` so they can be included,
excluded, or weighted independently:

  N1 url_param_not_ssrf   Real templates whose request carries a URL-valued
                          parameter but which are NOT SSRF (mostly open
                          redirect). The server does not fetch the URL; the
                          client does. Hardest and most valuable negatives,
                          because the request looks identical to an SSRF probe.
  N2 other_attack_class   Real attack templates for other vulnerability classes
                          (SQLi, XSS, RCE, path traversal...). Teaches "SSRF vs
                          other attack" rather than "attack vs normal".
  N3 benign_fingerprint   Real, non-attack GET requests (technology detection,
                          exposed panels). The easy negatives that set the base
                          rate.
  N4 counterfactual       For each SSRF positive, the same request with only
                          the payload swapped for a legitimate external URL.
                          Matched pairs: endpoint, headers, framework and
                          source are held fixed, so the payload is the only
                          thing that differs.
  N5 triaged_not_vuln     HackerOne SSRF reports the program closed as
                          Not Applicable or Informative. Real reports, real
                          HTTP, and the "not a vulnerability" judgement comes
                          from the program itself.

Honesty notes carried in the data:
  - N1, N2, N3 keep response evidence in the same `matcher_signature` form as
    the positives, so neither class has richer response data than the other.
  - N4 is CONSTRUCTED, not observed. Its `http_response` is null, because the
    real response was never captured. It is flagged `is_synthetic: true`.
    Use it for request-side models; exclude it from response-side models.

Usage:
    python3 build_negative_dataset.py /tmp/nt SSRF_NEGATIVE_DATASET.json
"""

import glob
import json
import os
import random
import re
import sys
from datetime import date

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extract_nuclei_ssrf as E  # noqa: E402

SEED = 20260923

# A parameter whose value is a URL. This is the shape an SSRF probe takes, so
# non-SSRF templates matching it are the hard negatives.
URL_PARAM = re.compile(r"[?&][\w.\[\]-]{1,30}=(?:https?%3a|https?:)//", re.I)

# Anything pointing at an internal or out-of-band destination. Templates that
# match are dropped from the negative pool: RFI/XXE/LFI probes aimed at
# 127.0.0.1 are SSRF-adjacent and would inject label noise.
INTERNAL_MARKER = re.compile(
    r"169\.254\.169\.254|127\.0\.0\.1|\blocalhost\b|\[::1\]|0\.0\.0\.0"
    r"|metadata\.google\.internal|100\.100\.100\.200"
    r"|interactsh|interact\.sh|oast\.|burpcollab|oastify|\.ngrok\."
    r"|(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+"
    r"|\bfile://|\bgopher://|\bdict://",
    re.I,
)

# The destination host a template uses for its callback is test scaffolding,
# not part of the vulnerability. Left in place inside a negative it becomes
# label leakage: the model would see an out-of-band host labelled benign in one
# class and malicious in the other. These are rewritten to a benign host and
# the row is flagged `destination_normalized`.
SCAFFOLD_URL = re.compile(
    # Consume any scheme and any leading subdomain labels, otherwise a payload
    # written as "http://www.interact.sh" is only partly replaced and produces
    # a mangled URL like "http://www.https://...".
    r"(?:https?://)?(?:[\w-]+\.)*"
    r"(?:\{\{interactsh-url\}\}|interact\.sh|oast\.(?:pro|live|site|fun|me|online)"
    r"|oastify\.com|burpcollaborator\.net)"
    r"[^\s\"'<>&\\]*",
    re.I,
)
NORMALIZED_HOST = "https://example-partner-api.com/callback"

# Real public hosts a legitimate integration would fetch. Used only to build
# the N4 counterfactuals.
BENIGN_HOSTS = [
    ("api.github.com", "/repos/octocat/hello-world"),
    ("registry.npmjs.org", "/express"),
    ("api.stripe.com", "/v1/charges"),
    ("hooks.slack.com", "/services/T0000/B0000/XXXX"),
    ("maps.googleapis.com", "/maps/api/geocode/json?address=Madrid"),
    ("api.openweathermap.org", "/data/2.5/weather?q=Madrid"),
    ("cdn.jsdelivr.net", "/npm/jquery@3.7.1/dist/jquery.min.js"),
    ("images.unsplash.com", "/photo-1503023345310-bd7c1de61c7d"),
    ("s3.eu-west-1.amazonaws.com", "/customer-assets/logo.png"),
    ("www.youtube.com", "/oembed?url=https://youtu.be/dQw4w9WgXcQ"),
    ("api.twilio.com", "/2010-04-01/Accounts.json"),
    ("gitlab.com", "/api/v4/projects/278964"),
    ("docs.google.com", "/document/d/e/2PACX/pub"),
    ("www.gravatar.com", "/avatar/205e460b479e2e5b48aec07710c08d50"),
    ("fonts.googleapis.com", "/css2?family=Inter"),
]

BENIGN_CATEGORIES = {"technologies", "exposed-panels", "osint", "default-logins"}


def load_all_templates(root):
    """Parse every http template once."""
    for path in sorted(glob.glob(os.path.join(root, "http", "**", "*.yaml"), recursive=True)):
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
            doc = yaml.safe_load(text)
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(doc, dict) or not (doc.get("http") or doc.get("requests")):
            continue
        yield os.path.relpath(path, root), doc


def first_request(doc):
    """The first concrete HTTP request in a template, or None."""
    entries = doc.get("http") or doc.get("requests") or []
    for entry in entries:
        payload_vars = entry.get("payloads") or {}
        for raw in entry.get("raw") or []:
            parsed = E.parse_raw(E.expand_payload_vars(raw, payload_vars))
            if parsed:
                return parsed, entry
        headers = dict(entry.get("headers") or {})
        for p in entry.get("path") or []:
            return {
                "method": entry.get("method", "GET"),
                "target": E.expand_payload_vars(p, payload_vars)
                          .replace("{{BaseURL}}", "").replace("{{RootURL}}", "") or "/",
                "protocol": "HTTP/1.1",
                "headers": headers,
                "body": E.expand_payload_vars(entry.get("body") or "", payload_vars) or None,
            }, entry
    return None, None


def response_block(entry):
    """Response evidence in the same shape the positives use."""
    ev = E.summarize_matchers(entry)
    return {
        "capture_type": "matcher_signature",
        "status_code": ev["expected_status"][0] if ev["expected_status"] else None,
        "expected_status_codes": ev["expected_status"] or None,
        "response_size_bytes": None,
        "response_time_ms": None,
        "content_type": E.content_type_from(ev),
        "body_evidence_words": ev["body_words"] or None,
        "body_evidence_regex": ev["body_regex"] or None,
        "header_evidence_words": ev["header_words"] or None,
        "oob_evidence_protocols": ev["oob_protocols"] or None,
        "dsl_expressions": ev["dsl"] or None,
        "matchers_condition": ev["matchers_condition"],
    }


def make_negative(eid, negative_type, rel_path, doc, req, entry, commit, extra=None):
    info = doc.get("info", {}) or {}
    cls = info.get("classification", {}) or {}
    meta = info.get("metadata", {}) or {}
    tags = info.get("tags") or ""
    if isinstance(tags, list):
        tags = ",".join(tags)

    row = {
        "example_id": eid,
        "is_vulnerable": False,
        "negative_type": negative_type,
        "is_synthetic": False,
        "data_source": "nuclei_templates_non_ssrf",
        "extraction_date": str(date.today()),
        "http_request": {
            "method": req["method"],
            "path": req["target"],
            "protocol": req["protocol"],
            "headers": req["headers"] or None,
            "body": {"raw": req["body"],
                     "content_type": (req["headers"] or {}).get("Content-Type")} if req["body"] else None,
            "has_url_valued_parameter": bool(URL_PARAM.search(req["target"] + (req["body"] or ""))),
        },
        "http_response": response_block(entry),
        "why_not_ssrf": None,  # filled by the caller
        "vulnerability_class": {
            "cwe_id": str(cls.get("cwe-id") or "") or None,
            "severity": info.get("severity"),
            "tags": tags,
        },
        "affected_application": {
            "name": info.get("name"),
            "vendor": meta.get("vendor"),
            "product": meta.get("product"),
        },
        "source": {
            "type": "nuclei_template",
            "cve_id": cls.get("cve-id"),
            "template_id": doc.get("id"),
            "template_path": rel_path,
            "template_repo": "https://github.com/projectdiscovery/nuclei-templates",
            "template_commit": commit,
            "references": info.get("reference") or [],
            "title": info.get("name"),
        },
    }
    if extra:
        row.update(extra)
    return row


def collect_nuclei_negatives(root, commit, n_other, n_benign):
    """Strata N1, N2 and N3."""
    rng = random.Random(SEED)
    n1, other_pool, benign_pool = [], [], []

    for rel_path, doc in load_all_templates(root):
        if E.is_ssrf_template(doc):
            continue
        req, entry = first_request(doc)
        if not req:
            continue
        def blob_of(r):
            # Headers count: templates park the callback host in `Host:` or a
            # custom header, and a leak there is just as poisonous.
            return "\n".join([r["target"], r["body"] or ""] +
                             [f"{k}: {v}" for k, v in (r["headers"] or {}).items()])

        blob = blob_of(req)
        has_url_param = bool(URL_PARAM.search(req["target"] + "\n" + (req["body"] or "")))

        # Rewrite callback scaffolding before deciding. Open-redirect templates
        # point at interact.sh purely to observe the redirect, and they are the
        # single most valuable negative stratum, so normalize rather than drop.
        normalized = False
        if SCAFFOLD_URL.search(blob):
            req = dict(req)
            req["target"] = SCAFFOLD_URL.sub(NORMALIZED_HOST, req["target"])
            if req["body"]:
                req["body"] = SCAFFOLD_URL.sub(NORMALIZED_HOST, req["body"])
            req["headers"] = {
                k: SCAFFOLD_URL.sub(NORMALIZED_HOST.split("//", 1)[1].split("/")[0], v)
                for k, v in (req["headers"] or {}).items()
            }
            blob = blob_of(req)
            normalized = True

        if INTERNAL_MARKER.search(blob):
            continue  # SSRF-adjacent even after normalizing; too risky

        category = rel_path.split(os.sep)[1] if os.sep in rel_path else rel_path.split("/")[1]
        item = (rel_path, doc, req, entry, category, normalized)
        if has_url_param or URL_PARAM.search(blob):
            n1.append(item)
        elif category in BENIGN_CATEGORIES:
            benign_pool.append(item)
        else:
            other_pool.append(item)

    rng.shuffle(other_pool)
    rng.shuffle(benign_pool)

    rows = []
    for i, (rel_path, doc, req, entry, _, normalized) in enumerate(n1, start=1):
        row = make_negative(f"NEG-URLPARAM-{i:04d}", "url_param_not_ssrf",
                            rel_path, doc, req, entry, commit,
                            extra={"destination_normalized": normalized})
        row["why_not_ssrf"] = (
            "The request carries a URL-valued parameter, so it has the same "
            "shape as an SSRF probe, but the vulnerability is client-side "
            "(open redirect or similar): the server returns the URL rather "
            "than fetching it."
        )
        rows.append(row)

    # Keep N2 spread across categories instead of letting http/cves dominate.
    by_cat = {}
    for item in other_pool:
        by_cat.setdefault(item[4], []).append(item)
    picked, idx = [], 0
    cats = sorted(by_cat)
    while len(picked) < n_other and any(by_cat.values()):
        cat = cats[idx % len(cats)]
        if by_cat.get(cat):
            picked.append(by_cat[cat].pop())
        idx += 1
    for i, (rel_path, doc, req, entry, _, normalized) in enumerate(picked, start=1):
        row = make_negative(f"NEG-OTHERATK-{i:04d}", "other_attack_class",
                            rel_path, doc, req, entry, commit,
                            extra={"destination_normalized": normalized})
        row["why_not_ssrf"] = (
            "A real attack request for a different vulnerability class. No "
            "attacker-controlled destination is passed to a server-side fetch."
        )
        rows.append(row)

    for i, (rel_path, doc, req, entry, _, normalized) in enumerate(benign_pool[:n_benign], start=1):
        row = make_negative(f"NEG-BENIGN-{i:04d}", "benign_fingerprint",
                            rel_path, doc, req, entry, commit,
                            extra={"destination_normalized": normalized})
        row["why_not_ssrf"] = (
            "An ordinary request with no attack payload: technology detection "
            "or a panel/login page fetch."
        )
        rows.append(row)

    return rows, len(n1), len(other_pool), len(benign_pool)


def swap_payload(target, body, payload, host, path):
    """Replace the SSRF payload with a legitimate external URL."""
    benign = f"https://{host}{path}"
    if not payload:
        return target, body, benign
    new_target = target.replace(payload, benign) if payload in target else target
    new_body = body
    if body and payload in body:
        new_body = body.replace(payload, benign)
    # The payload may only appear percent-encoded in the request.
    if new_target == target and (not body or new_body == body):
        from urllib.parse import quote
        enc = quote(payload, safe="")
        if enc in target:
            new_target = target.replace(enc, quote(benign, safe=""))
        elif body and enc in body:
            new_body = body.replace(enc, quote(benign, safe=""))
    return new_target, new_body, benign


def build_counterfactuals(positives_path):
    """Stratum N4: matched pairs, one per SSRF positive."""
    rng = random.Random(SEED + 1)
    data = json.load(open(positives_path, encoding="utf-8"))
    rows = []
    for i, pos in enumerate(data.get("examples", []), start=1):
        req = pos["http_request"]
        payload = (pos.get("payload") or {}).get("raw_payload")
        if not payload:
            continue  # cannot build a clean counterfactual without the payload
        host, path = rng.choice(BENIGN_HOSTS)
        new_target, new_body, benign = swap_payload(
            req["path"], (req.get("body") or {}).get("raw"), payload, host, path
        )
        if new_target == req["path"] and new_body == ((req.get("body") or {}).get("raw")):
            continue  # substitution did not apply; skip rather than fake it

        # The payload is not always the only internal reference: XML and SOAP
        # bodies often carry a second one. A negative that still contains
        # 127.0.0.1 or a metadata IP is label leakage, so sanitize the rest and
        # drop the row if anything survives.
        new_target = SCAFFOLD_URL.sub(benign, new_target)
        if new_body:
            new_body = SCAFFOLD_URL.sub(benign, new_body)
        new_headers = {k: SCAFFOLD_URL.sub(host, v)
                       for k, v in (req.get("headers") or {}).items()}
        check = "\n".join([new_target, new_body or ""] +
                          [f"{k}: {v}" for k, v in new_headers.items()])
        if INTERNAL_MARKER.search(check):
            continue

        rows.append({
            "example_id": f"NEG-CF-{i:04d}",
            "is_vulnerable": False,
            "negative_type": "counterfactual",
            "is_synthetic": True,
            "data_source": "counterfactual_from_nuclei_positive",
            "extraction_date": str(date.today()),
            "derived_from": pos["example_id"],
            "matched_pair_id": pos["example_id"],
            "http_request": {
                "method": req["method"],
                "path": new_target,
                "protocol": req["protocol"],
                "headers": new_headers or None,
                "body": {"raw": new_body,
                         "content_type": (req.get("body") or {}).get("content_type")} if new_body else None,
                "has_url_valued_parameter": True,
            },
            "payload": {
                "raw_payload": benign,
                "payload_classification": {
                    "destination_category": "external_legitimate",
                    "protocol": "https",
                    "is_internal": False,
                    "is_oob": False,
                },
                "bypass_techniques": ["none_required"],
            },
            # Never observed: the real application was never asked this.
            "http_response": None,
            "why_not_ssrf": (
                "Same endpoint, same headers, same application as the matched "
                "positive. Only the destination changed, from an internal or "
                "out-of-band target to a legitimate external host."
            ),
            "affected_application": pos.get("affected_application"),
            "source": dict(pos.get("source") or {}, type="counterfactual_of_nuclei_template"),
        })
    return rows


def build_hackerone_negatives(harvest_path):
    """Stratum N5: SSRF reports the program judged not to be vulnerabilities."""
    if not os.path.exists(harvest_path):
        return []
    data = json.load(open(harvest_path, encoding="utf-8"))
    rows = []
    for i, rep in enumerate(data.get("reports", []), start=1):
        if rep.get("substate") not in ("not-applicable", "informative"):
            continue
        if not rep.get("raw_http_requests"):
            continue
        rows.append({
            "example_id": f"NEG-H1-{rep['report_id']}",
            "is_vulnerable": False,
            "negative_type": "triaged_not_vuln",
            "is_synthetic": False,
            "data_source": "hackerone_public_disclosure",
            "extraction_date": str(date.today()),
            "raw_http_requests": rep["raw_http_requests"],
            "raw_http_responses": rep.get("raw_http_responses") or [],
            "why_not_ssrf": (
                f"Reported as SSRF but closed by the program as "
                f"{rep.get('substate')}, so the behaviour was judged not to be "
                f"a vulnerability."
            ),
            "source": {
                "type": "hackerone",
                "id": rep["report_id"],
                "url": rep["url"],
                "title": rep.get("title"),
                "substate": rep.get("substate"),
                "hackerone_cwe": rep.get("hacktivity_cwe"),
                "disclosed_at": rep.get("disclosed_at"),
            },
        })
    return rows


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "/tmp/nt"
    out = sys.argv[2] if len(sys.argv) > 2 else "SSRF_NEGATIVE_DATASET.json"
    n_other = int(os.environ.get("N_OTHER", 150))
    n_benign = int(os.environ.get("N_BENIGN", 150))

    commit = os.popen(f"git -C {root} rev-parse HEAD").read().strip() or None

    nuclei_rows, n1_avail, n2_avail, n3_avail = collect_nuclei_negatives(root, commit, n_other, n_benign)
    cf_rows = build_counterfactuals("SSRF_CVE_DATASET_NUCLEI.json")
    h1_rows = build_hackerone_negatives("SSRF_HACKERONE_RAW_HTTP.json")

    rows = nuclei_rows + cf_rows + h1_rows
    counts = {}
    for r in rows:
        counts[r["negative_type"]] = counts.get(r["negative_type"], 0) + 1

    dataset = {
        "dataset_info": {
            "version": "1.0",
            "name": "ssrf_negative_dataset",
            "creation_date": str(date.today()),
            "total_examples": len(rows),
            "vulnerable_count": 0,
            "benign_count": len(rows),
            "by_negative_type": counts,
            "observed_vs_constructed": {
                "observed_real_requests": sum(1 for r in rows if not r["is_synthetic"]),
                "constructed_counterfactuals": sum(1 for r in rows if r["is_synthetic"]),
            },
            "pool_sizes_available": {
                "url_param_not_ssrf": n1_avail,
                "other_attack_class": n2_avail,
                "benign_fingerprint": n3_avail,
            },
            "source_commit": commit,
            "seed": SEED,
            "notes": (
                "Negatives drawn from the same corpus and pipeline as the "
                "positives, so the classes cannot be separated by source "
                "artefacts. Filter on `negative_type`: counterfactual rows are "
                "constructed and carry no observed response, so exclude them "
                "from response-side models."
            ),
        },
        "examples": rows,
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(dataset, fh, indent=2, ensure_ascii=False)

    print(f"negatives: {len(rows)}")
    for k, v in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {k:24s} {v}")
    print(f"pools available: url_param={n1_avail} other={n2_avail} benign={n3_avail}")
    print("written:", out)


if __name__ == "__main__":
    main()
