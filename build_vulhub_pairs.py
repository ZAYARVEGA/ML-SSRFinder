#!/usr/bin/env python3
"""
Turn the captured vulhub responses into matched vulnerable / non-vulnerable
rows that share the feature_schema of response_dataset_final.json.

Unlike every other source in this project, both sides of each pair are real
observed responses from the SAME running binary at the SAME instant: the
vulnerable request that performs the SSRF, and a non-vulnerable request to the
same endpoint that does not. There is therefore no temporal caveat (unlike the
same-site negatives in Source D) and the response is real (unlike the
constructed counterfactual stratum). This is the control Reviewer 2 R2-6 asks
for, closed properly.

Input:  results/<app>_{vuln,neg_counterfactual,neg_benign}.json
        (produced by the capture harness against the podman/vulhub targets)
Output: SSRF_VULHUB_PAIRS.json

The featurizer is imported from parse_raw_http_to_features.py so extraction is
byte-for-byte identical to the rest of the corpus. The one field the other
sources could never fill, response_time_ms, is populated here from the real
measurement, and the timing / content / status differentials are computed
across each matched pair.
"""

import json
import os
import sys

import parse_raw_http_to_features as F

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "vulhub_capture", "results")

# One entry per environment. capture files are the raw harness output.
ENVIRONMENTS = [
    {
        "app": "geoserver", "version": "2.19.1", "cve": "CVE-2021-40822",
        "image": "vulhub/geoserver:2.19.1",
        "endpoint": "/geoserver/TestWfsPost", "ssrf_type": "full_read",
        "vuln": "geoserver_vuln.json",
        "negs": [("geoserver_neg_counterfactual.json", "url_param_not_ssrf",
                  "same TestWfsPost endpoint, Host does not match url so the "
                  "server refuses to fetch"),
                 ("geoserver_neg_benign.json", "benign_fingerprint",
                  "normal GET to the GeoServer web console")],
    },
    {
        "app": "grafana", "version": "8.5.4", "cve": "grafana-admin-ssrf",
        "image": "vulhub/grafana:8.5.4",
        "endpoint": "/api/datasources/proxy/{id}/", "ssrf_type": "full_read",
        "vuln": "grafana_vuln.json",
        "negs": [("grafana_neg_counterfactual.json", "url_param_not_ssrf",
                  "same datasource-proxy endpoint pointed at a non-existent "
                  "datasource id, so no fetch happens"),
                 ("grafana_neg_benign.json", "benign_fingerprint",
                  "normal /api/health call")],
    },
    {
        "app": "php-xxe", "version": "php7.0.30-libxml2.8.0", "cve": "php-xxe-ssrf",
        "image": "vulhub/php:7.0.30",
        "endpoint": "/dom.php", "ssrf_type": "blind_oob",
        "vuln": "phpxxe_vuln.json",
        "negs": [("phpxxe_neg_counterfactual.json", "url_param_not_ssrf",
                  "same dom.php endpoint with a benign XML document, no "
                  "external entity, so no fetch")],
    },
    {
        "app": "apache-cxf", "version": "3.2.14", "cve": "CVE-2024-28752",
        "image": "vulhub/apache-cxf:3.2.14",
        "endpoint": "/test", "ssrf_type": "full_read",
        "vuln": "cxf_vuln.json",
        "negs": [("cxf_neg_counterfactual.json", "url_param_not_ssrf",
                  "same SOAP endpoint with an xop:Include href that resolves "
                  "to no attachment, so no fetch"),
                 ("cxf_neg_benign.json", "benign_fingerprint",
                  "normal ?wsdl service description request")],
    },
    {
        "app": "solr", "version": "8.8.1", "cve": "solr-remote-streaming",
        "image": "vulhub/solr:8.8.1",
        "endpoint": "/solr/demo/debug/dump", "ssrf_type": "full_read",
        "vuln": "solr_vuln.json",
        "negs": [("solr_neg_counterfactual.json", "url_param_not_ssrf",
                  "same debug/dump endpoint without stream.url, so no fetch"),
                 ("solr_neg_benign.json", "benign_fingerprint",
                  "normal admin/ping health check")],
    },
]


def raw_block(cap):
    """Rebuild a raw HTTP response block from a structured capture so the
    project featurizer sees exactly what it sees for every other source."""
    status = cap["status_code"]
    lines = [f"HTTP/1.1 {status} X"]
    for k, v in (cap.get("headers") or {}).items():
        lines.append(f"{k}: {v}")
    head = "\r\n".join(lines)
    body = cap.get("body_excerpt", "")
    return head + "\r\n\r\n" + body


def featurize(cap):
    resp = F.parse_response(raw_block(cap))
    # The scarce field the static sources could never provide: real timing.
    resp["response_time_ms"] = cap.get("response_time_ms")
    # response_size_bytes from the capture is the full body length; the
    # rebuilt block only carries the 600-char excerpt, so prefer the measured
    # size and full char length.
    resp["response_size_bytes"] = cap.get("response_size_bytes")
    resp["capture_type"] = "live_observed"
    return resp


def main():
    rows = []
    pair_seq = 0
    for env in ENVIRONMENTS:
        vcap = json.load(open(os.path.join(RESULTS, env["vuln"])))
        vresp = featurize(vcap)
        pair_seq += 1
        pid = f"VULHUB-{env['app'].upper()}-{pair_seq:03d}"
        vrow = {
            "example_id": f"{pid}-V",
            "matched_pair_id": pid,
            "source": {
                "corpus": "vulhub", "app": env["app"], "version": env["version"],
                "cve": env["cve"], "image": env["image"],
                "endpoint": env["endpoint"],
                "collection": "podman, live SSRF against an internal target "
                              "under our control (127.0.0.1:9999); no payload "
                              "sent to any third party",
            },
            "target": f"{env['app']} {env['version']} (self-hosted vulhub)",
            "is_vulnerable": True,
            "is_synthetic": False,
            "temporal_caveat": None,
            "ssrf_type": env["ssrf_type"],
            "severity": "high",
            "http_response": vresp,
        }
        rows.append(vrow)

        for negfile, negtype, why in env["negs"]:
            ncap = json.load(open(os.path.join(RESULTS, negfile)))
            nresp = featurize(ncap)
            # pair differentials, computed across the real pair
            nresp["is_status_differential"] = vresp["status_code"] != nresp["status_code"]
            nresp["status_alive_host"] = vresp["status_code"]
            nresp["status_dead_host"] = nresp["status_code"]
            if vresp["response_time_ms"] and nresp["response_time_ms"]:
                nresp["is_timing_differential"] = (
                    vresp["response_time_ms"] > 2 * nresp["response_time_ms"]
                )
                nresp["timing_open_port_ms"] = vresp["response_time_ms"]
                nresp["timing_closed_port_ms"] = nresp["response_time_ms"]
            nresp["is_content_differential"] = (
                vresp["response_size_bytes"] != nresp["response_size_bytes"]
            )
            nrow = {
                "example_id": f"{pid}-N-{negtype}",
                "matched_pair_id": pid,
                "source": dict(vrow["source"], negative_reason=why),
                "target": vrow["target"],
                "is_vulnerable": False,
                "negative_type": negtype,
                "is_synthetic": False,
                "temporal_caveat": None,
                "ssrf_type": None,
                "severity": None,
                "http_response": nresp,
            }
            rows.append(nrow)

    out = {
        "dataset_info": {
            "name": "SSRF_VULHUB_PAIRS",
            "description": "Matched vulnerable / non-vulnerable SSRF responses "
                           "captured live from self-hosted vulhub environments. "
                           "Both sides of each pair come from the same binary at "
                           "the same instant. No temporal caveat, real observed "
                           "responses, same feature_schema as "
                           "response_dataset_final.json.",
            "source": "Source E (vulhub, self-hosted via podman)",
            "environments": len(ENVIRONMENTS),
            "n_examples": len(rows),
            "n_vulnerable": sum(1 for r in rows if r["is_vulnerable"]),
            "n_non_vulnerable": sum(1 for r in rows if not r["is_vulnerable"]),
            "capture_type": "live_observed",
            "note": "response_time_ms is a real measurement here, unlike the "
                    "matcher_signature sources. is_synthetic is false for both "
                    "classes.",
        },
        "examples": rows,
    }
    outpath = os.path.join(HERE, "SSRF_VULHUB_PAIRS.json")
    json.dump(out, open(outpath, "w"), indent=2)
    print(f"wrote {outpath}: {len(rows)} rows "
          f"({out['dataset_info']['n_vulnerable']}v / "
          f"{out['dataset_info']['n_non_vulnerable']}n) "
          f"from {len(ENVIRONMENTS)} environments")


if __name__ == "__main__":
    main()
