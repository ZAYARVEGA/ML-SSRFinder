#!/usr/bin/env python3
"""
Sanity check on the negative class: is it actually hard, or does it just look
like a different kind of traffic?

A negative class that a trivial model separates perfectly inflates the reported
metrics without making the detector better. This script trains a small
request-side model on the positives plus the negatives and reports accuracy
BROKEN DOWN BY negative stratum, so it is visible which negatives carry signal.

It also runs the ablation Reviewer 2 asked for in R2-6: refit with the
destination-identity features removed, to see how much of the performance comes
from simply spotting a private IP literal.

Usage:
    python3 check_negative_difficulty.py
"""

import json
import re
from collections import Counter

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold

PRIVATE_IP = re.compile(
    r"169\.254\.169\.254|127\.0\.0\.1|\blocalhost\b|\[::1\]|0\.0\.0\.0"
    r"|metadata\.google\.internal|100\.100\.100\.200"
    r"|(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+",
    re.I,
)
OOB = re.compile(r"interactsh|interact\.sh|oast\.|oastify|burpcollaborator", re.I)
URL_PARAM_NAME = re.compile(
    r"[?&]([\w.\[\]-]{1,30})=(?:https?%3a|https?:)//", re.I)
SSRF_ISH_PARAM = re.compile(
    r"\b(url|uri|link|src|source|target|dest|destination|redirect|next|data|"
    r"path|file|page|feed|host|port|to|out|view|domain|callback|webhook|"
    r"proxy|fetch|load|image|img|remote)\b", re.I)

# Features whose whole job is to name the destination. The ablation drops these.
DESTINATION_FEATURES = {"has_private_ip", "has_oob_host", "scheme_non_http"}


def request_text(ex):
    req = ex.get("http_request") or {}
    parts = [req.get("method") or "", req.get("path") or ""]
    body = req.get("body") or {}
    if isinstance(body, dict):
        parts.append(body.get("raw") or "")
    for k, v in (req.get("headers") or {}).items():
        parts.append(f"{k}: {v}")
    return "\n".join(parts)


def featurize(ex):
    text = request_text(ex)
    req = ex.get("http_request") or {}
    path = req.get("path") or ""
    param_names = URL_PARAM_NAME.findall(text)
    return {
        "has_private_ip": int(bool(PRIVATE_IP.search(text))),
        "has_oob_host": int(bool(OOB.search(text))),
        "scheme_non_http": int(bool(re.search(r"\b(file|gopher|dict|ldap|sftp|jar)://", text, re.I))),
        "has_url_param": int(bool(URL_PARAM_NAME.search(text))),
        "url_param_is_ssrf_ish": int(any(SSRF_ISH_PARAM.fullmatch(p) for p in param_names)),
        "n_query_params": path.count("&") + (1 if "?" in path else 0),
        "is_post": int((req.get("method") or "GET").upper() != "GET"),
        "has_body": int(bool((req.get("body") or {}).get("raw") if isinstance(req.get("body"), dict) else False)),
        "path_depth": path.split("?")[0].count("/"),
        "path_len": min(len(path), 300),
        "has_encoded_chars": int(bool(re.search(r"%[0-9a-f]{2}", path, re.I))),
        "has_double_encoding": int(bool(re.search(r"%25[0-9a-f]{2}", path, re.I))),
        "has_auth_header": int(any(k.lower() in ("authorization", "cookie")
                                   for k in (req.get("headers") or {}))),
    }


def load():
    rows = []
    pos = json.load(open("SSRF_CVE_DATASET_NUCLEI.json", encoding="utf-8"))
    for e in pos["examples"]:
        rows.append((featurize(e), 1, "positive_nuclei"))
    neg = json.load(open("SSRF_NEGATIVE_DATASET.json", encoding="utf-8"))
    for e in neg["examples"]:
        if not e.get("http_request"):
            continue  # triaged_not_vuln rows keep raw text, not a parsed request
        rows.append((featurize(e), 0, e["negative_type"]))
    return rows


def evaluate(rows, drop=()):
    names = [k for k in rows[0][0] if k not in drop]
    X = np.array([[r[0][k] for k in names] for r in rows], dtype=float)
    y = np.array([r[1] for r in rows])
    groups = [r[2] for r in rows]

    correct = np.zeros(len(y), dtype=bool)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=0)
    for tr, te in skf.split(X, y):
        clf = RandomForestClassifier(n_estimators=300, random_state=0, n_jobs=-1)
        clf.fit(X[tr], y[tr])
        correct[te] = clf.predict(X[te]) == y[te]

    clf = RandomForestClassifier(n_estimators=300, random_state=0, n_jobs=-1).fit(X, y)
    importance = sorted(zip(names, clf.feature_importances_), key=lambda x: -x[1])
    return correct, groups, importance, y


def report(title, rows, drop=()):
    correct, groups, importance, y = evaluate(rows, drop)
    print(f"\n{'=' * 68}\n{title}\n{'=' * 68}")
    print(f"overall accuracy (5-fold): {correct.mean():.3f}")
    per = {}
    for ok, g in zip(correct, groups):
        per.setdefault(g, []).append(ok)
    print("\naccuracy by stratum (low = the model genuinely struggles = useful negatives):")
    for g, vals in sorted(per.items(), key=lambda x: np.mean(x[1])):
        print(f"  {g:24s} n={len(vals):4d}  acc={np.mean(vals):.3f}")
    print("\ntop features:")
    for name, imp in importance[:6]:
        print(f"  {name:26s} {imp:.3f}")


def main():
    rows = load()
    print("class balance:", Counter(r[1] for r in rows))
    report("ALL FEATURES", rows)

    # The OOB host is nuclei's callback scaffolding, and it was stripped from
    # the negatives to stop them leaking the label. Leaving it in the positives
    # therefore hands the model a corpus artefact rather than a symptom of
    # SSRF. Dropping it alone isolates how much of the score was that artefact.
    report("ABLATION: OOB host feature removed (corpus artefact)",
           rows, drop={"has_oob_host"})

    report("ABLATION: all destination-identity features removed (R2-6)",
           rows, drop=DESTINATION_FEATURES)


if __name__ == "__main__":
    main()
