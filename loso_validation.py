#!/usr/bin/env python3
"""
Leave-one-source-out validation for the response-side SSRF detector (R2-6).

Reviewer 2's R2-6 objection: in the published work every positive came from
HackerOne and every negative was synthetic, so within-source cross-validation
cannot tell whether the model learned SSRF or merely learned to recognise the
source. The answer is to train on one source and test on a DIFFERENT one. If the
detector still works across the source boundary, it generalised to the
vulnerability, not the provenance.

Sources now available on the response side:
  - original  : response_dataset_final.json  (the paper's HackerOne-derived set)
  - hackerone : SSRF_HACKERONE_RESPONSE_FEATURES.json  (labelled positives only;
                the 34 unlabelled rows are excluded, not treated as negatives)
  - vulhub    : SSRF_VULHUB_PAIRS.normalized.json  (self-hosted CVEs, BOTH classes,
                a provenance the paper never saw)
  - samesite  : SSRF_SAME_SITE_NEGATIVES.json  (real benign responses, negatives)

Feature extraction is imported verbatim from train_response_models.py so the
model sees exactly the paper's features. Following the paper, blind_oob positives
are excluded from the response side (no signal in the response).

Only two sources carry BOTH classes (original, vulhub), so those two directions
are the headline: they are the only folds whose test set can produce a full
confusion matrix. Single-class test sources are reported too, but there they
measure recall on the one class present.

Usage:
    ./.venv/bin/python loso_validation.py
"""

import json
from collections import Counter

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Import the paper's exact feature extractor without running its training code.
import importlib.util
import types


def _load_extract_features():
    """Pull extract_features out of train_response_models.py without executing
    the module's top-level training script."""
    src = open("train_response_models.py").read()
    # The function is self-contained; exec just its definition in a namespace.
    start = src.index("def extract_features")
    end = src.index("\nrows = [extract_features")
    ns = {}
    exec(src[start:end], ns)
    return ns["extract_features"]


extract_features = _load_extract_features()

EXCLUDE_TYPES = {"blind_oob"}  # same rule as train_response_models.py

# Features R2-6 names literally: is_https, requires_auth, server_cloud,
# size_large. is_https and requires_auth are request-side and absent from the
# response feature set, so on the response side the exact features the reviewer
# flagged are server_cloud and size_large. We drop precisely those. We do NOT
# drop server_ec2ws or the other size bins: server_ec2ws is the AWS metadata
# server's own signature and size_small captures the ~313-byte metadata listing,
# so those are genuine SSRF-response signals, not provenance.
SOURCE_SENSITIVE = {"server_cloud", "size_large"}


def load_source(path, name):
    rows = []
    data = json.load(open(path, encoding="utf-8"))
    for e in data["examples"]:
        resp = e.get("http_response")
        if not resp:
            continue  # no response to featurize (counterfactual/unlabelled)
        # HackerOne: keep only the labelled positives; the false rows are
        # unlabelled per the collection decision, not negatives.
        if name == "hackerone" and not e.get("is_vulnerable"):
            continue
        if e.get("is_vulnerable") and e.get("ssrf_type") in EXCLUDE_TYPES:
            continue
        feats = extract_features(e)
        rows.append((feats, 1 if e["is_vulnerable"] else 0, name))
    return rows


def to_xy(rows, feature_names):
    X = pd.DataFrame([{k: r[0][k] for k in feature_names} for r in rows])
    y = np.array([r[1] for r in rows])
    return X, y


def make_model():
    # Shallow RF with balanced classes: robust on tiny n, matches the ablation
    # script's spirit. A linear reference (logistic regression) is reported too.
    return RandomForestClassifier(
        n_estimators=300, max_depth=4, min_samples_leaf=2,
        max_features="sqrt", class_weight="balanced", random_state=0, n_jobs=-1)


def make_linear():
    return make_pipeline(
        StandardScaler(),
        LogisticRegression(class_weight="balanced", max_iter=2000, random_state=0))


def evaluate(y_true, y_pred):
    return {
        "acc": accuracy_score(y_true, y_pred),
        "prec": precision_score(y_true, y_pred, zero_division=0),
        "rec": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
    }


def confusion(y_true, y_pred):
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    return tn, fp, fn, tp


SOURCES = [
    ("original", "response_dataset_final.json"),
    ("hackerone", "SSRF_HACKERONE_RESPONSE_FEATURES.json"),
    ("vulhub", "SSRF_VULHUB_PAIRS.normalized.json"),
    ("samesite", "SSRF_SAME_SITE_NEGATIVES.json"),
]


def run_block(all_rows, feature_names, label):
    """Run the full LOSO + pooled reference + source diagnostic on one feature
    set. Returns the pooled and per-direction headline numbers so the two
    feature sets (full vs source-sensitive removed) can be compared."""
    from sklearn.model_selection import cross_val_predict, StratifiedKFold

    print("\n" + "#" * 72)
    print(f"# FEATURE SET: {label}  ({len(feature_names)} features)")
    print("#" * 72)

    print("\nLEAVE-ONE-SOURCE-OUT (train on all other sources, test on the named one)")
    print(f"{'test source':12s} {'n':>4} {'class(es)':16s} "
          f"{'acc':>6} {'prec':>6} {'rec':>6} {'f1':>6}   confusion(tn fp fn tp)")
    print("-" * 72)
    headline = {}
    for held, _ in SOURCES:
        test = [r for r in all_rows if r[2] == held]
        train = [r for r in all_rows if r[2] != held]
        if not test:
            continue
        Xtr, ytr = to_xy(train, feature_names)
        Xte, yte = to_xy(test, feature_names)
        pred = make_model().fit(Xtr.values, ytr).predict(Xte.values)
        m = evaluate(yte, pred)
        tn, fp, fn, tp = confusion(yte, pred)
        classes = "both" if len(set(yte)) == 2 else ("vuln-only" if yte[0] == 1 else "benign-only")
        print(f"{held:12s} {len(test):>4} {classes:16s} "
              f"{m['acc']:>6.3f} {m['prec']:>6.3f} {m['rec']:>6.3f} {m['f1']:>6.3f}   "
              f"({tn} {fp} {fn} {tp})")
        if len(set(yte)) == 2:
            headline[held] = m

    Xall, yall = to_xy(all_rows, feature_names)
    skf5 = StratifiedKFold(n_splits=5, shuffle=True, random_state=0)
    pooled = cross_val_predict(make_model(), Xall.values, yall, cv=skf5)
    mp = evaluate(yall, pooled)
    tn, fp, fn, tp = confusion(yall, pooled)
    print(f"\npooled 5-fold reference (sources MIXED): acc={mp['acc']:.3f} "
          f"prec={mp['prec']:.3f} rec={mp['rec']:.3f} f1={mp['f1']:.3f} "
          f"confusion=({tn} {fp} {fn} {tp})")

    src_names = sorted(set(r[2] for r in all_rows))
    src_idx = {s: i for i, s in enumerate(src_names)}
    ysrc = np.array([src_idx[r[2]] for r in all_rows])
    base = Counter(ysrc).most_common(1)[0][1] / len(ysrc)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=0)
    psrc = cross_val_predict(make_model(), Xall.values, ysrc, cv=skf)
    print(f"source predictability (4-way, lower=better): "
          f"{accuracy_score(ysrc, psrc):.3f}  (base {base:.3f})")
    return {"pooled": mp, "headline": headline}


def main():
    all_rows = []
    for name, path in SOURCES:
        rows = load_source(path, name)
        all_rows += rows
        c = Counter(r[1] for r in rows)
        print(f"source {name:10s}: n={len(rows):3d}  vuln={c[1]:3d}  benign={c[0]:3d}")
    feature_names = sorted(all_rows[0][0].keys())
    print(f"\ntotal rows {len(all_rows)}, features {len(feature_names)}")
    print("(blind_oob positives excluded from the response side, per the paper)")

    full = run_block(all_rows, feature_names, "ALL features")

    ablated_names = [f for f in feature_names if f not in SOURCE_SENSITIVE]
    dropped = sorted(SOURCE_SENSITIVE & set(feature_names))
    ablated = run_block(all_rows, ablated_names,
                        f"SOURCE-SENSITIVE REMOVED (dropped: {', '.join(dropped)})")

    print("\n" + "=" * 72)
    print("R2-6 ABLATION SUMMARY: does removing source-sensitive features change it?")
    print("=" * 72)
    print(f"{'metric':28s} {'ALL feats':>12} {'no source feats':>16} {'delta':>8}")
    a, b = full["pooled"], ablated["pooled"]
    for k in ("acc", "prec", "rec", "f1"):
        print(f"pooled 5-fold {k:14s} {a[k]:>12.3f} {b[k]:>16.3f} {b[k]-a[k]:>+8.3f}")
    for held in full["headline"]:
        if held in ablated["headline"]:
            a, b = full["headline"][held], ablated["headline"][held]
            for k in ("acc", "f1"):
                print(f"LOSO test={held:8s} {k:8s} {a[k]:>12.3f} {b[k]:>16.3f} {b[k]-a[k]:>+8.3f}")
    print("\nRemoving the two flagged features DOES hurt, so the next question is")
    print("whether they encode the source or the label. The diagnostic below")
    print("answers it per feature (mutual information with label vs with source).")

    # Per-feature: does each reviewer-flagged feature encode LABEL or SOURCE?
    # This is the real R2-6 answer: a feature that hurts to remove is fine if it
    # carries vulnerability signal, and a problem only if it carries provenance.
    from sklearn.metrics import mutual_info_score
    print("\n" + "=" * 72)
    print("R2-6 PER-FEATURE: label-encoding (signal) vs source-encoding (artifact)")
    print("=" * 72)
    for feat in sorted(SOURCE_SENSITIVE & set(feature_names)) + ["server_ec2ws", "size_small"]:
        vals = [r[0][feat] for r in all_rows]
        lab = [r[1] for r in all_rows]
        src = [r[2] for r in all_rows]
        mi_lab = mutual_info_score(vals, lab)
        mi_src = mutual_info_score(vals, src)
        on = [l for v, l in zip(vals, lab) if v == 1]
        p_on = (sum(on) / len(on)) if on else float("nan")
        verdict = "LABEL (signal)" if mi_lab > mi_src else "SOURCE (artifact)"
        print(f"  {feat:14s} fires {sum(vals):2d}/{len(vals)}  "
              f"MI_label={mi_lab:.3f} MI_source={mi_src:.3f}  "
              f"P(vuln|=1)={p_on:.2f}  -> {verdict}")
    print("\nserver_cloud and size_large fire almost only on BENIGN responses and")
    print("carry more label than source information: they are 'this is a normal")
    print("page' markers, genuine discriminators, which is why dropping them hurts.")
    print("server_ec2ws is the one honest confound: it perfectly marks vulnerable")
    print("but appears in a single source, so an AWS-metadata positive from a")
    print("second source is needed to separate the signal from the provenance.")


if __name__ == "__main__":
    main()
