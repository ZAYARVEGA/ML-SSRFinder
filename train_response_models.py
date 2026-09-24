#!/usr/bin/env python3
"""
SSRF Response Detector - Multi-Model Training
=============================================
Trains and compares 3 models on HTTP response features:
  1. XGBoost    - Gradient Boosting (baseline)
  2. Random Forest - Bagging ensemble
  3. SVM (RBF)  - Maximum margin classifier

Dataset: response_dataset_final.json
Excludes: blind_oob examples (no signal in response)
"""

import json
import numpy as np
import pandas as pd
import pickle
import warnings
warnings.filterwarnings('ignore')

from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import StratifiedKFold, cross_val_score, LeaveOneOut
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)
from xgboost import XGBClassifier

# ─────────────────────────────────────────────
# 1. LOAD & FILTER DATASET
# ─────────────────────────────────────────────

with open('response_dataset_final.json') as f:
    raw = json.load(f)

# Exclude blind_oob — no response signal
EXCLUDE_TYPES = ['blind_oob']
examples = [
    e for e in raw['examples']
    if e.get('ssrf_type') not in EXCLUDE_TYPES
]

print(f"Total examples after filtering blind_oob: {len(examples)}")
print(f"  Vulnerable : {sum(1 for e in examples if e['is_vulnerable'])}")
print(f"  Benign     : {sum(1 for e in examples if not e['is_vulnerable'])}")
print()

# ─────────────────────────────────────────────
# 2. FEATURE EXTRACTION
# ─────────────────────────────────────────────

def extract_features(example: dict) -> dict:
    """
    Extract numeric/boolean features from an http_response block.
    All features must be computable at runtime from a real HTTP response.
    """
    r = example['http_response']

    # Status code signals
    status = r.get('status_code') or 0
    status_2xx     = 1 if 200 <= status < 300 else 0
    status_4xx     = 1 if 400 <= status < 500 else 0
    status_5xx     = 1 if 500 <= status < 600 else 0
    status_is_200  = 1 if status == 200 else 0
    status_is_400  = 1 if status == 400 else 0
    status_is_403  = 1 if status == 403 else 0
    status_is_404  = 1 if status == 404 else 0
    status_is_502  = 1 if status == 502 else 0

    # Response size
    size = r.get('response_size_bytes') or 0
    size_small   = 1 if 0 < size < 500 else 0    # typical metadata listing ~313 bytes
    size_medium  = 1 if 500 <= size < 5000 else 0
    size_large   = 1 if size >= 5000 else 0

    # Response time
    rt = r.get('response_time_ms') or 0
    time_fast    = 1 if 0 < rt < 100 else 0       # closed port / blocked
    time_medium  = 1 if 100 <= rt < 1000 else 0
    time_slow    = 1 if rt >= 1000 else 0          # open port / SSRF timing

    # Server header signals
    server = (r.get('server_header') or '').lower()
    server_ec2ws   = 1 if 'ec2ws' in server else 0      # AWS metadata server signature
    server_nginx   = 1 if 'nginx' in server else 0
    server_apache  = 1 if 'apache' in server else 0
    server_cloud   = 1 if any(x in server for x in ['cloudflare', 'github', 'amazons3']) else 0
    server_istio   = 1 if 'istio' in server else 0

    # Content-type signals
    ct = (r.get('content_type') or '').lower()
    ct_json        = 1 if 'json' in ct else 0
    ct_text_plain  = 1 if ct.strip().startswith('text/plain') else 0
    ct_html        = 1 if 'html' in ct else 0
    ct_xml         = 1 if 'xml' in ct else 0
    ct_image       = 1 if 'image' in ct else 0

    # Body content signals (the strongest features)
    body_aws_meta  = int(r.get('body_has_aws_metadata', False))
    body_creds     = int(r.get('body_has_credentials', False))
    body_oob_echo  = int(r.get('body_has_oob_echo', False))
    body_error_j   = int(r.get('body_has_error_json', False))
    body_bearer    = int(r.get('body_has_bearer_token', False))
    body_internal  = int(r.get('body_has_internal_service_info', False))

    # Body structure signals
    struct = (r.get('body_structure') or '').lower()
    struct_metadata   = 1 if 'metadata_listing' in struct else 0
    struct_creds_json = 1 if 'credentials_json' in struct else 0
    struct_error      = 1 if 'error' in struct else 0
    struct_success    = 1 if struct in ['success_json', 'xml_response'] and not struct_error else 0
    struct_html_pub   = 1 if 'public' in struct else 0

    # Differential signals (timing / status / content)
    is_timing_diff  = int(r.get('is_timing_differential', False))
    is_status_diff  = int(r.get('is_status_differential', False))
    is_content_diff = int(r.get('is_content_differential', False))
    timing_open     = r.get('timing_open_port_ms') or 0
    timing_closed   = r.get('timing_closed_port_ms') or 0
    timing_ratio    = (timing_open / timing_closed) if timing_closed > 0 else 0

    # Unusual headers
    unusual = r.get('unusual_headers') or []
    has_unusual_headers = 1 if len(unusual) > 0 else 0
    has_auth_header     = 1 if any('auth' in str(h).lower() for h in unusual) else 0
    has_forwarded       = 1 if any('forward' in str(h).lower() for h in unusual) else 0

    # Composite: content-type mismatch (API returning text/plain = suspicious)
    ct_mismatch = 1 if ct_text_plain and not body_error_j else 0

    return {
        # Status
        'status_is_200':         status_is_200,
        'status_is_400':         status_is_400,
        'status_is_403':         status_is_403,
        'status_is_404':         status_is_404,
        'status_is_502':         status_is_502,
        'status_4xx':            status_4xx,
        'status_5xx':            status_5xx,
        # Size
        'size_small':            size_small,
        'size_medium':           size_medium,
        'size_large':            size_large,
        # Timing
        'time_slow':             time_slow,
        'timing_ratio':          timing_ratio,
        # Server
        'server_ec2ws':          server_ec2ws,
        'server_istio':          server_istio,
        'server_cloud':          server_cloud,
        # Content-type
        'ct_text_plain':         ct_text_plain,
        'ct_json':               ct_json,
        'ct_xml':                ct_xml,
        'ct_mismatch':           ct_mismatch,
        # Body keywords (strongest features)
        'body_aws_meta':         body_aws_meta,
        'body_creds':            body_creds,
        'body_oob_echo':         body_oob_echo,
        'body_error_json':       body_error_j,
        'body_bearer':           body_bearer,
        'body_internal_info':    body_internal,
        # Body structure
        'struct_metadata':       struct_metadata,
        'struct_creds_json':     struct_creds_json,
        'struct_error':          struct_error,
        # Differentials
        'is_timing_diff':        is_timing_diff,
        'is_status_diff':        is_status_diff,
        'is_content_diff':       is_content_diff,
        # Headers
        'has_auth_header':       has_auth_header,
        'has_forwarded':         has_forwarded,
    }


rows = [extract_features(e) for e in examples]
labels = [1 if e['is_vulnerable'] else 0 for e in examples]

X = pd.DataFrame(rows)
y = np.array(labels)
feature_names = list(X.columns)

print(f"Feature matrix: {X.shape[0]} samples × {X.shape[1]} features")
print(f"Label distribution: {sum(y==1)} vulnerable, {sum(y==0)} benign")
print()

# ─────────────────────────────────────────────
# 3. EVALUATION STRATEGY
# ─────────────────────────────────────────────
# n=28 is small → use Leave-One-Out CV for most reliable estimate
# Also run Stratified 5-Fold for comparison

loo = LeaveOneOut()
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

def evaluate_model(model, X, y, model_name, needs_scaling=False):
    """Full evaluation: LOO-CV + Stratified 5-Fold + final fit.

    R2-8 fix: the StandardScaler is now fit INSIDE each fold, never on the whole
    dataset before splitting. Fitting the scaler once on all rows (the previous
    behaviour) leaks test-fold statistics into training and inflates the SVM
    score. During evaluation we therefore refit a fresh scaler per fold; the
    scaler stored with the deployed model is fit on all training data, which is
    correct because at deployment there is no held-out fold.
    """
    X_arr = X.values

    # LOO-CV (scaler refit within each fold)
    loo_preds = []
    loo_true  = []
    for train_idx, test_idx in loo.split(X_arr):
        Xtr, Xte = X_arr[train_idx], X_arr[test_idx]
        ytr, yte = y[train_idx], y[test_idx]
        if needs_scaling:
            fold_scaler = StandardScaler().fit(Xtr)
            Xtr, Xte = fold_scaler.transform(Xtr), fold_scaler.transform(Xte)
        m = type(model)(**model.get_params())
        m.fit(Xtr, ytr)
        loo_preds.append(m.predict(Xte)[0])
        loo_true.append(yte[0])

    loo_acc  = accuracy_score(loo_true, loo_preds)
    loo_prec = precision_score(loo_true, loo_preds, zero_division=0)
    loo_rec  = recall_score(loo_true, loo_preds, zero_division=0)
    loo_f1   = f1_score(loo_true, loo_preds, zero_division=0)
    loo_cm   = confusion_matrix(loo_true, loo_preds)

    # 5-Fold CV: wrap scaling + model in a pipeline so the scaler is fit on the
    # training part of each fold only, never on the held-out part.
    cv_estimator = make_pipeline(StandardScaler(), type(model)(**model.get_params())) \
        if needs_scaling else model
    skf_acc  = cross_val_score(cv_estimator, X_arr, y, cv=skf, scoring='accuracy').mean()
    skf_f1   = cross_val_score(cv_estimator, X_arr, y, cv=skf, scoring='f1').mean()
    skf_prec = cross_val_score(cv_estimator, X_arr, y, cv=skf, scoring='precision').mean()
    skf_rec  = cross_val_score(cv_estimator, X_arr, y, cv=skf, scoring='recall').mean()

    # Final fit on all data. The deployed scaler is fit on all training rows
    # (correct: no held-out fold exists at deployment) and stored alongside the
    # model, so the .pkl keeps the same {model, scaler, needs_scaling} shape.
    if needs_scaling:
        scaler = StandardScaler().fit(X_arr)
        X_fit = scaler.transform(X_arr)
    else:
        scaler = None
        X_fit = X_arr
    model.fit(X_fit, y)
    train_acc = accuracy_score(y, model.predict(X_fit))

    return {
        'model_name':    model_name,
        'model':         model,
        'scaler':        scaler,
        'needs_scaling': needs_scaling,
        'feature_names': feature_names,
        # LOO results (most reliable for small n)
        'loo_accuracy':  loo_acc,
        'loo_precision': loo_prec,
        'loo_recall':    loo_rec,
        'loo_f1':        loo_f1,
        'loo_cm':        loo_cm,
        'loo_preds':     loo_preds,
        'loo_true':      loo_true,
        # 5-Fold results
        'skf_accuracy':  skf_acc,
        'skf_precision': skf_prec,
        'skf_recall':    skf_rec,
        'skf_f1':        skf_f1,
        # Training accuracy
        'train_accuracy': train_acc,
    }

# ─────────────────────────────────────────────
# 4. DEFINE MODELS
# ─────────────────────────────────────────────

models = {
    'XGBoost': XGBClassifier(
        n_estimators=100,
        max_depth=3,           # shallow trees → less overfit
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=0.1,         # L1 regularization
        reg_lambda=1.0,        # L2 regularization
        use_label_encoder=False,
        eval_metric='logloss',
        random_state=42,
        verbosity=0
    ),
    'Random Forest': RandomForestClassifier(
        n_estimators=200,
        max_depth=4,           # shallow to prevent overfit on n=28
        min_samples_leaf=2,    # at least 2 samples per leaf
        max_features='sqrt',
        bootstrap=True,
        random_state=42,
        class_weight='balanced'
    ),
    'SVM (RBF)': SVC(
        kernel='rbf',
        C=1.0,                 # regularization strength
        gamma='scale',         # auto-scale to features
        probability=True,      # for confidence scores
        class_weight='balanced',
        random_state=42
    ),
}

needs_scaling = {
    'XGBoost':       False,
    'Random Forest': False,
    'SVM (RBF)':     True,   # SVM requires normalized features
}

# ─────────────────────────────────────────────
# 5. TRAIN & EVALUATE ALL MODELS
# ─────────────────────────────────────────────

print("=" * 65)
print("TRAINING & EVALUATING 3 MODELS")
print("=" * 65)

results = {}
for name, model in models.items():
    print(f"\n[{name}] Training...")
    res = evaluate_model(model, X, y, name, needs_scaling=needs_scaling[name])
    results[name] = res
    print(f"  Done. LOO Accuracy: {res['loo_accuracy']:.1%}  F1: {res['loo_f1']:.1%}")

# ─────────────────────────────────────────────
# 6. COMPARISON TABLE
# ─────────────────────────────────────────────

print("\n")
print("=" * 65)
print("RESULTS — LEAVE-ONE-OUT CROSS VALIDATION (most reliable, n=28)")
print("=" * 65)
print(f"{'Metric':<22} {'XGBoost':>12} {'Rnd Forest':>12} {'SVM (RBF)':>12}")
print("-" * 60)

metrics = [
    ('LOO Accuracy',  'loo_accuracy'),
    ('LOO Precision', 'loo_precision'),
    ('LOO Recall',    'loo_recall'),
    ('LOO F1',        'loo_f1'),
]
for label, key in metrics:
    vals = [results[n][key] for n in models]
    best_idx = vals.index(max(vals))
    row = f"{label:<22}"
    for i, (n, v) in enumerate(zip(models, vals)):
        marker = " ✓" if i == best_idx else "  "
        row += f" {v:>10.1%}{marker}"
    print(row)

print()
print("=" * 65)
print("RESULTS — STRATIFIED 5-FOLD CV")
print("=" * 65)
print(f"{'Metric':<22} {'XGBoost':>12} {'Rnd Forest':>12} {'SVM (RBF)':>12}")
print("-" * 60)

skf_metrics = [
    ('5-Fold Accuracy',  'skf_accuracy'),
    ('5-Fold Precision', 'skf_precision'),
    ('5-Fold Recall',    'skf_recall'),
    ('5-Fold F1',        'skf_f1'),
]
for label, key in skf_metrics:
    vals = [results[n][key] for n in models]
    best_idx = vals.index(max(vals))
    row = f"{label:<22}"
    for i, (n, v) in enumerate(zip(models, vals)):
        marker = " ✓" if i == best_idx else "  "
        row += f" {v:>10.1%}{marker}"
    print(row)

print()
print("=" * 65)
print("CONFUSION MATRICES — LOO-CV")
print("=" * 65)
for name in models:
    cm = results[name]['loo_cm']
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    print(f"\n  [{name}]")
    print(f"  {'':12} Pred Benign  Pred Vuln")
    print(f"  {'Real Benign':<12}     {tn:>4}        {fp:>4}   {'← False Positives (bad in pentesting)' if fp > 0 else '✓ Zero FP'}")
    print(f"  {'Real Vuln':<12}     {fn:>4}        {tp:>4}   {'← False Negatives (missed vulns)' if fn > 0 else '✓ Zero FN'}")

# ─────────────────────────────────────────────
# 7. FEATURE IMPORTANCE (tree models)
# ─────────────────────────────────────────────

print()
print("=" * 65)
print("FEATURE IMPORTANCE (XGBoost & Random Forest)")
print("=" * 65)

for name in ['XGBoost', 'Random Forest']:
    model = results[name]['model']
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    print(f"\n  [{name}] Top 10 features:")
    for i in range(min(10, len(feature_names))):
        idx = indices[i]
        bar = '█' * int(importances[idx] * 60)
        print(f"  {feature_names[idx]:<26} {importances[idx]:.4f}  {bar}")

# ─────────────────────────────────────────────
# 8. WINNER ANALYSIS
# ─────────────────────────────────────────────

print()
print("=" * 65)
print("WINNER ANALYSIS")
print("=" * 65)

scores = {}
for name in models:
    r = results[name]
    # Weighted score: F1 (40%) + Precision (40%) + Recall (20%)
    # Pentesting bias: precision > recall (no queremos FP)
    scores[name] = (
        r['loo_f1']        * 0.40 +
        r['loo_precision'] * 0.40 +
        r['loo_recall']    * 0.20
    )

ranked = sorted(scores.items(), key=lambda x: -x[1])
print("\n  Ranking (F1×0.4 + Precision×0.4 + Recall×0.2):")
for rank, (name, score) in enumerate(ranked, 1):
    r = results[name]
    cm = r['loo_cm']
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    print(f"  #{rank} {name:<16} Score={score:.3f}  FP={fp}  FN={fn}")

winner = ranked[0][0]
print(f"\n  🏆 WINNER: {winner}")
print(f"     F1={results[winner]['loo_f1']:.1%}  "
      f"Precision={results[winner]['loo_precision']:.1%}  "
      f"Recall={results[winner]['loo_recall']:.1%}")

# ─────────────────────────────────────────────
# 9. SAVE ALL MODELS
# ─────────────────────────────────────────────

print()
print("=" * 65)
print("SAVING MODELS")
print("=" * 65)

for name in models:
    r = results[name]
    filename = name.lower().replace(' ', '_').replace('(', '').replace(')', '') + '_response.pkl'
    save_data = {
        'model':         r['model'],
        'scaler':        r['scaler'],
        'feature_names': feature_names,
        'needs_scaling': r['needs_scaling'],
        'metrics': {
            'loo_accuracy':  r['loo_accuracy'],
            'loo_precision': r['loo_precision'],
            'loo_recall':    r['loo_recall'],
            'loo_f1':        r['loo_f1'],
            'skf_accuracy':  r['skf_accuracy'],
            'skf_f1':        r['skf_f1'],
        },
        'training_info': {
            'n_samples':   len(examples),
            'n_vulnerable': sum(y),
            'n_benign':    len(y) - sum(y),
            'cv_method':   'LeaveOneOut + StratifiedKFold-5',
            'dataset':     'response_dataset_final.json (blind_oob excluded)',
        }
    }
    with open(filename, 'wb') as f:
        pickle.dump(save_data, f)
    print(f"  ✓ Saved: {filename}  ({r['loo_accuracy']:.1%} LOO accuracy)")

print("\nDone.")
