# SSRF data sources (September 2026 collection)

New real-world SSRF data collected to broaden the training set beyond the
original HackerOne-only corpus. The motivation is Reviewer 2 comment R2-6
(source bias / leave-one-source-out validation): the published dataset drew all
its positives from HackerOne and all its negatives from synthetic examples, so
a model can separate the classes by learning the source rather than the
vulnerability.

Everything below comes from public, unauthenticated endpoints.

## Source A: nuclei-templates CVE corpus

| | |
|---|---|
| File | `SSRF_CVE_DATASET_NUCLEI.json` |
| Script | `extract_nuclei_ssrf.py` |
| Upstream | https://github.com/projectdiscovery/nuclei-templates |
| Commit pinned | `75b0b8c8d9b1ba6caf4bee44b40a2358a9bb5796` (2026-09-23) |
| Examples | 219 (all positives) |
| CVE-backed | 165, all classified CWE-918 |
| Years covered | 2014 to 2026 |

Each example holds the verbatim attack request (method, path, headers, body),
the resolved injection point, the SSRF payload, the detected bypass technique,
and the response evidence that confirms exploitation.

**Label provenance.** Positives are templates whose CWE is 918, whose tag list
contains `ssrf`, or whose title names SSRF. A plain full-text match was tried
first and rejected: it pulled in XSS and RCE templates that merely mention SSRF
in prose.

**Limitation to state in the paper.** A nuclei template encodes the response
*signature* that confirms exploitation (expected status codes, body words,
header words, OOB protocol), not a captured response body. So
`response_size_bytes` and `response_time_ms` are null for this source, and
`http_response.capture_type` is `matcher_signature`. Models trained on
size/timing features cannot use this source; models trained on request-side and
body-keyword features can.

Fields that support filtering before training:

- `http_request.injection_details.injection_resolved` — false for 18 examples
  whose payload is base64-wrapped, XXE-wrapped, or buried in multipart data.
- `vulnerability.ssrf_type` — `full_read` 120, `blind_oob` 63, `blind_status`
  25, `blind_header` 1, `unspecified` 10.
- `http_request.multi_step` — 70 examples need preceding requests (login, nonce
  fetch); those are kept in `precondition_requests`, not as separate examples.

## Source B: HackerOne raw HTTP harvest

| | |
|---|---|
| Files | `SSRF_HACKERONE_RAW_HTTP.json` (raw), `SSRF_HACKERONE_RESPONSE_FEATURES.json` (parsed) |
| Scripts | `harvest_hackerone_ssrf.py`, `parse_raw_http_to_features.py` |
| Search hits | 361 disclosed reports matching `ssrf` |
| With raw HTTP text | 69 |
| With request **and** response | 30 |
| Confirmed positives after parsing | 22 rows across 15 reports |
| Net new (not already in the project datasets) | 12 reports |

`parse_raw_http_to_features.py` emits rows using the **same `feature_schema` as
`response_dataset_final.json`**, so they concatenate directly with the existing
training data.

**Yield is low, and that is the finding.** Only 69 of 361 disclosed SSRF reports
contain raw HTTP as text; the rest document the exploit with screenshots or
attachments. Any claim that a dataset was built from "HackerOne SSRF reports"
should carry this number, because it bounds how large a text-extractable
HackerOne corpus can be.

**Label provenance.** A row is `is_vulnerable: true` only when HackerOne's own
CWE label is Server-Side Request Forgery, the report substate is `resolved`, and
the write-up contains an internal-target marker. The remaining 34 rows are kept
with `is_vulnerable: false` and should be treated as unlabelled, not as
negatives. 18 rows carry `needs_manual_review: true`.

**Known weakness in the parser.** Requests and responses are paired by position
in the write-up (nearest preceding request), because that is how researchers
write them. Reports that interleave several attempts can still mispair; those
rows are the ones flagged for review. Check `matched_request` before trusting
any request-side feature.

## Source C: the negative class

| | |
|---|---|
| File | `SSRF_NEGATIVE_DATASET.json` |
| Script | `build_negative_dataset.py` |
| Examples | 584, all negatives |
| Observed (real requests) | 420 |
| Constructed (counterfactuals) | 164 |

Negatives are drawn from the **same corpus and the same extraction pipeline** as
the positives, so the classes cannot be told apart by source artefacts. Five
strata, selectable through `negative_type`:

| Stratum | n | Pool available | What it is |
|---|---|---|---|
| `url_param_not_ssrf` | 117 | 117 | Real templates whose request carries a URL-valued parameter but which are **not** SSRF, almost all open redirect. The server returns the URL instead of fetching it. Hardest and most valuable. |
| `other_attack_class` | 150 | 7081 | Real attack requests for other classes (SQLi, XSS, RCE, traversal). Teaches "SSRF vs other attack", not "attack vs normal". |
| `benign_fingerprint` | 150 | 4112 | Real non-attack GETs (technology detection, panels). Sets the base rate. |
| `counterfactual` | 164 | 219 | Each SSRF positive with **only the payload swapped** for a legitimate external URL. Matched pairs via `matched_pair_id`. |
| `triaged_not_vuln` | 3 | 3 | HackerOne SSRF reports the program closed as Not Applicable or Informative. |

Raise `N_OTHER` / `N_BENIGN` env vars to draw more from the large pools.

**Label-leakage controls applied.** Any template whose request touched an
internal or out-of-band destination was dropped from the negative pool; a
negative containing `127.0.0.1` would teach the model the opposite of the
truth. Callback scaffolding in `Host:` headers and in bodies is sanitized too,
not just in the path, and rows where anything survived were discarded. Verified:
**0 negatives contain an internal or OOB marker**.

**`counterfactual` is constructed, not observed.** Its `http_response` is
`null`, because the real application was never asked that question. Use it for
request-side models; exclude it from response-side models. It is flagged
`is_synthetic: true`.

## The artefact this uncovered, and why it matters for the paper

`check_negative_difficulty.py` trains a small request-side random forest on
positives plus negatives and reports accuracy per stratum. The first run:

| Setting | Overall acc | Positive recall |
|---|---|---|
| All features | 0.955 | 0.877 |
| Remove **one** feature, "contains an OOB host" | 0.696 | 0.342 |

That single feature held 63% of the model's importance. nuclei uses a callback
host (`{{interactsh-url}}`, `*.oast.pro`, `interact.sh`) to observe blind SSRF,
so it appears in most positives, and it had to be stripped from the negatives to
stop them leaking the label. The model was therefore recognising **nuclei's test
scaffolding, not SSRF**.

`normalize_corpus_artefacts.py` fixes this by rewriting the callback host to one
neutral `attacker-controlled.example` in **both** classes, producing
`*.normalized.json`. This is semantically faithful: a blind SSRF payload is an
attacker-controlled external URL, and the specific domain does not change
whether the server fetches it. **Train on the `.normalized.json` files.**

Honest baseline on the normalized corpus with 13 crude request-side features:

```
overall accuracy 0.675      positive recall 0.306
benign_fingerprint  0.947   <- easy, as expected
url_param_not_ssrf  0.872
other_attack_class  0.853
counterfactual      0.616   <- matched pairs are genuinely hard
positive_nuclei     0.306
```

The conclusion to carry into the paper: once the scaffolding artefact is
removed, a blind-SSRF positive and an open-redirect negative are close to
indistinguishable **from the request alone**, since both are
`?url=<attacker host>`. That is not a flaw in the data, it is the ceiling of
request-only detection, and it is the argument for the response-side model.
Any reported request-side metric should be accompanied by this ablation.

## Source D: same-site negatives (real observed responses)

| | |
|---|---|
| File | `SSRF_SAME_SITE_NEGATIVES.json` |
| Script | `collect_same_site_negatives.py` |
| Hosts attempted | 12 |
| Collected | 10 |
| **Exact same-page pairs with a positive** | **5** |
| Unreachable | 2 (SSL handshake, DNS gone) |

Non-vulnerable responses collected **live from the same web applications** that
appear as SSRF positives, so a positive and a negative share the exact host and
endpoint and the difference is the vulnerability, not the source. This is the
control R2-6 asks for, with real observed responses (unlike the constructed
`counterfactual` stratum).

**Collection method, and its hard limit.** One benign GET per host, with the
SSRF parameter removed. The SSRF payload is **never** sent to a live third
party: doing so would exercise the vulnerability on someone else's server. So
only the non-vulnerable side is collected here; the vulnerable side stays the
archived response from the write-up. Endpoints requiring auth answer 401/403/404,
which is itself a valid non-vulnerable baseline for that exact page.

**Temporal caveat, recorded per row in `temporal_caveat`.** The benign response
is captured now, from the patched production server, a different version and a
different point in time than the archived vulnerable response. The pair shares
the URL, not the server state. State this in the paper; do not claim the two
responses are contemporaneous.

The five same-page pairs (archived vulnerable vs benign now):

| Host | Vulnerable (archived) | Benign (collected) |
|---|---|---|
| couriers.indrive.com | 200, OOB echo in body | 404, ordinary HTML |
| summit.acronis.events | 200, AWS IMDS listing | 200, normal event page |
| search.usa.gov | 200, empty (blind) | 202, help page |
| 667667.myshopify.com | 422 JSON error | 200 storefront HTML |
| www.first.org | 200, fetched text | 200, homepage HTML |

**Featurizer bug fixed while doing this.** `body_has_internal_service_info` was
matching `<title>`/`<html>`, so it fired on every HTML page, and
`body_has_aws_metadata` fired on benign AWS-SDK JavaScript (e.g. the Shopify
storefront). Both regexes in `parse_raw_http_to_features.py` were tightened to
require real internal-service tokens / distinctive IMDS paths. This fix also
applies to the HackerOne positives, which share the module. After the fix: 0/10
benign responses show spurious AWS metadata (was 1), and 1/10 shows an
internal-service token (was 8), that one beyond the stored excerpt.

**Effect on source balance.** HackerOne moves from 63 vulnerable / 3
non-vulnerable to **63 / 13**, and 5 of those negatives are exact same-page
pairs. Corpus-only label predictability drops from 0.742 to 0.734 against a
0.679 majority-class base.

## Source E: self-hosted vulhub pairs (both classes, same binary, same instant)

| | |
|---|---|
| Files | `SSRF_VULHUB_PAIRS.json` (+ `.normalized.json`) |
| Scripts | `build_vulhub_pairs.py`, capture harness in `scratchpad/capture.py` |
| Environments attempted | 12 (the SSRF-tagged entries in vulhub) |
| Environments captured | 5 (geoserver, grafana, php-xxe, apache-cxf, solr) |
| Examples | 14 (5 vulnerable, 9 non-vulnerable) |
| Matched pairs | 9 (each negative shares the exact endpoint of its positive) |

This is the control R2-6 asks for, closed properly. Every other source pairs a
vulnerable response with a negative from a different time (Source D) or a
constructed one with no response at all (the `counterfactual` stratum). Here
**both sides of each pair are real observed responses from the same running
binary at the same instant**: the request that performs the SSRF, and a request
to the same endpoint that does not. No temporal caveat, and `is_synthetic` is
false for both classes.

**What each environment is.**

| App | Version | CVE | SSRF type | Vuln vs same-endpoint negative |
|---|---|---|---|---|
| geoserver | 2.19.1 | CVE-2021-40822 | full_read | 200 (105 B, internal JSON) vs 200 (199 B, servlet error) |
| grafana | 8.5.4 | admin datasource SSRF | full_read | 200 (internal JSON) vs 404 (no datasource) |
| php-xxe | php7.0.30/libxml2.8.0 | XXE-SSRF | blind_oob | 200 (6.2 ms, fetch) vs 200 (0.4 ms, no fetch) |
| apache-cxf | 3.2.14 | CVE-2024-28752 | full_read | 500 (internal leaked base64) vs 500 (no attachment) |
| solr | 8.8.1 | RemoteStreaming | full_read | 200 (682 B, internal JSON) vs 200 (349 B, no stream.url) |

**Why these pairs matter more than their count (14 rows).** Look at the status
codes: in three of five environments the vulnerable and the same-endpoint
negative return the **same** status (200/200 for geoserver, php-xxe, solr;
500/500 for apache-cxf). A model cannot separate them on status. The signal
lives where it actually lives for SSRF: leaked internal content
(`body_has_internal_service_info`), response size, and for the blind cases a
real timing gap (php-xxe 0.4 ms to 6.2 ms; apache-cxf 3.5 ms to 44.5 ms). This
is exactly the argument for the response-side model, now on pairs where source
is held constant by construction. It also shows why the non-vulnerable side
could not be written by hand: the honest responses are 404, 202, 500, and
same-size 200s, not the 403 one would assume.

**Real timing.** `response_time_ms` is a genuine measurement here, so these 5
positives and 9 negatives join the scarce 108 literally-captured responses
(Source D and the HackerOne set) rather than the 636 matcher signatures. They
are the only rows that carry a controlled open-port / closed-port timing pair
from the same host.

**Method, and its guardrails.** Each environment was run rootless with podman
(`--network host`), the SSRF was pointed only at an internal target under our
control (`127.0.0.1:9999`, a small server returning a fake IMDS-style JSON), and
**no SSRF payload was ever sent to a live third party**. The internal target's
unique literal token is rewritten to a placeholder by
`normalize_corpus_artefacts.py` so no model can memorize it, exactly as the OOB
host is; the private IP and `secret_token` keyword are kept because a leaked
internal service is the true full_read signal, not an artefact.

**Not captured, and why.** adminer (`vulhub/adminer:4.7.8`) and one ffmpeg image
have been removed from Docker Hub. apisix CVE-2021-45232 is RCE-first and
multi-container with a CRC-checksummed import, a poor fit for an SSRF response
dataset. weblogic 10.3.6 and ofbiz are heavy JVMs that would not stay up under
rootless host networking in the time available; httpd CVE-2021-40438 needs a
custom image build. These remain the obvious way to grow the pair count.

## What is still missing

1. **More vulhub pairs.** Source E captured 5 of 12 SSRF environments. weblogic,
   ofbiz, httpd (needs build), and apisix are the remaining reproducible ones;
   each would add real same-binary pairs and more so full_read/blind variety.
2. **HTTP DATASET CSIC 2010.** 36,000 normal requests plus 25,000 anomalous
   ones, already a standard benchmark in this literature. Cheap to add and
   citable, but it does not come from the same applications as the positives,
   so it controls source bias only partially.
   https://www.tic.itefi.csic.es/dataset/

## Reproducing

```bash
git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/projectdiscovery/nuclei-templates.git /tmp/nt
cd /tmp/nt && git sparse-checkout set http && git checkout 75b0b8c8

pip install pyyaml
python3 extract_nuclei_ssrf.py /tmp/nt SSRF_CVE_DATASET_NUCLEI.json
python3 harvest_hackerone_ssrf.py SSRF_HACKERONE_RAW_HTTP.json --max 400 --delay 0.7
python3 parse_raw_http_to_features.py SSRF_HACKERONE_RAW_HTTP.json \
    SSRF_HACKERONE_RESPONSE_FEATURES.json

# negatives
python3 build_negative_dataset.py /tmp/nt SSRF_NEGATIVE_DATASET.json

# Source E: self-hosted vulhub pairs (needs podman; rootless is fine)
#   pacman -S podman crun passt netavark aardvark-dns fuse-overlayfs
#   git clone --depth 1 https://github.com/vulhub/vulhub.git
# For each captured environment: podman run --network host the pinned image,
# start scratchpad/internal/srv.py on 127.0.0.1:9999, run the README PoC with
# url/stream/href pointing at 127.0.0.1:9999, and capture vuln + same-endpoint
# negative with scratchpad/capture.py into scratchpad/results/. Then:
python3 build_vulhub_pairs.py              # -> SSRF_VULHUB_PAIRS.json

# strip the corpus artefacts from ALL classes/files
python3 normalize_corpus_artefacts.py      # writes the *.normalized.json to train on

pip install scikit-learn numpy
python3 check_negative_difficulty.py       # the ablation table above
```

The harvest takes about 10 minutes at the default delay. `pyyaml` is needed
beyond the standard library; Source E additionally needs `podman` and the
`vulhub` repo.

## Licensing and attribution

- nuclei-templates: MIT. Per-example provenance is kept in `source`
  (`template_path`, `template_commit`, `author`, `references`).
- HackerOne: only reports the researcher and program agreed to disclose
  publicly. Each row keeps `report_url` and the reporter handle. Redaction
  blocks (`████`) present in the originals are preserved as-is.
