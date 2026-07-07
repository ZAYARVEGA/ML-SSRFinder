#!/usr/bin/env python3
"""
Passive (request-level) SSRF ML training and evaluation.

Trains an XGBoost classifier on the 40-example request dataset
(BALANCED_DATASET_40_EXAMPLES.json) using the same boolean request-structure
feature family used by the deployed detector
(mlssrfinder-detector.py extract_features), and reports
Leave-One-Out and Stratified 5-Fold cross-validation metrics.

This produces the REAL passive-mode triage numbers reported in the paper.
"""

import json
import numpy as np
import pandas as pd
import warnings
warnings.filterwarnings('ignore')

from sklearn.model_selection import LeaveOneOut, StratifiedKFold, cross_val_score
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix)
from xgboost import XGBClassifier

with open('BALANCED_DATASET_40_EXAMPLES.json') as f:
    data = json.load(f)
examples = data['examples']

def request_features(ex):
    req = ex['http_request']
    url = (req.get('url') or '').lower()
    method = (req.get('method') or 'GET').upper()
    body = req.get('body') or {}
    param = (body.get('parameter_name') or '') or ''
    # also consider injection vulnerable_parameter
    inj = req.get('injection_details') or {}
    param = (param or (inj.get('vulnerable_parameter') or '')).lower()
    headers = req.get('headers') or {}
    requires_auth = bool(headers.get('Authorization')) or bool(inj.get('requires_authentication'))

    pl = param
    return {
        'param_url':        int('url' in pl),
        'param_webhook':    int(any(t in pl for t in ('webhook', 'hook'))),
        'param_redirect':   int(any(t in pl for t in ('redirect', 'redir', 'return', 'next'))),
        'param_callback':   int(any(t in pl for t in ('callback', 'cb'))),
        'param_dest':       int(any(t in pl for t in ('dest', 'target', 'path', 'uri'))),
        'param_file':       int(any(t in pl for t in ('file', 'load', 'src', 'img', 'image'))),
        'endpoint_api':     int('/api/' in url),
        'endpoint_fetch':   int(any(t in url for t in ('fetch', 'download', 'import'))),
        'endpoint_webhook': int(any(t in url for t in ('webhook', 'hook'))),
        'endpoint_proxy':   int('proxy' in url),
        'is_https':         int(url.startswith('https://')),
        'requires_auth':    int(requires_auth),
        'method_post':      int(method == 'POST'),
        'has_query_params': int('?' in url),
    }

rows = [request_features(e) for e in examples]
y = np.array([1 if e['is_vulnerable'] else 0 for e in examples])
X = pd.DataFrame(rows)
feature_names = list(X.columns)

print(f"Request dataset: {X.shape[0]} samples x {X.shape[1]} features")
print(f"Label distribution: {int(sum(y==1))} vulnerable, {int(sum(y==0))} benign")
print()

model = XGBClassifier(
    n_estimators=100, max_depth=3, learning_rate=0.1,
    subsample=0.8, colsample_bytree=0.8, reg_alpha=0.1, reg_lambda=1.0,
    use_label_encoder=False, eval_metric='logloss', random_state=42, verbosity=0,
)

# LOO-CV
loo = LeaveOneOut()
preds, true = [], []
Xv = X.values
for tr, te in loo.split(Xv):
    m = XGBClassifier(**model.get_params())
    m.fit(Xv[tr], y[tr])
    preds.append(int(m.predict(Xv[te])[0]))
    true.append(int(y[te][0]))

acc = accuracy_score(true, preds)
prec = precision_score(true, preds, zero_division=0)
rec = recall_score(true, preds, zero_division=0)
f1 = f1_score(true, preds, zero_division=0)
cm = confusion_matrix(true, preds)

print("=" * 60)
print("PASSIVE REQUEST-LEVEL XGBoost - LEAVE-ONE-OUT CV (n=40)")
print("=" * 60)
print(f"  Accuracy : {acc:.4f} ({acc:.1%})")
print(f"  Precision: {prec:.4f} ({prec:.1%})")
print(f"  Recall   : {rec:.4f} ({rec:.1%})")
print(f"  F1       : {f1:.4f} ({f1:.1%})")
tn, fp, fn, tp = cm.ravel()
print(f"  Confusion matrix [TN={tn} FP={fp} FN={fn} TP={tp}]")

# 5-fold
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
skf_acc  = cross_val_score(model, Xv, y, cv=skf, scoring='accuracy').mean()
skf_prec = cross_val_score(model, Xv, y, cv=skf, scoring='precision').mean()
skf_rec  = cross_val_score(model, Xv, y, cv=skf, scoring='recall').mean()
skf_f1   = cross_val_score(model, Xv, y, cv=skf, scoring='f1').mean()
print()
print("=" * 60)
print("PASSIVE REQUEST-LEVEL XGBoost - STRATIFIED 5-FOLD CV")
print("=" * 60)
print(f"  Accuracy : {skf_acc:.4f}")
print(f"  Precision: {skf_prec:.4f}")
print(f"  Recall   : {skf_rec:.4f}")
print(f"  F1       : {skf_f1:.4f}")

# feature importance (final fit)
model.fit(Xv, y)
imp = model.feature_importances_
order = np.argsort(imp)[::-1]
print()
print("=" * 60)
print("PASSIVE XGBoost - FEATURE IMPORTANCE (top 10)")
print("=" * 60)
for i in range(min(10, len(feature_names))):
    idx = order[i]
    print(f"  {feature_names[idx]:<20} {imp[idx]:.4f}")

# Save trained model to pkl with same schema as response models
import pickle
pkl_data = {
    'model':         model,
    'scaler':        None,
    'feature_names': feature_names,
    'needs_scaling': False,
    'metrics': {
        'loo_accuracy':  acc,
        'loo_precision': prec,
        'loo_recall':    rec,
        'loo_f1':        f1,
        'skf_accuracy':  skf_acc,
        'skf_precision': skf_prec,
        'skf_recall':    skf_rec,
        'skf_f1':        skf_f1,
    },
    'training_info': {
        'n_samples':  int(X.shape[0]),
        'n_features': int(X.shape[1]),
        'n_vuln':     int(sum(y == 1)),
        'n_benign':   int(sum(y == 0)),
        'dataset':    'BALANCED_DATASET_40_EXAMPLES.json',
    },
}
with open('xgboost_request.pkl', 'wb') as f:
    pickle.dump(pkl_data, f)
print()
print("Saved: xgboost_request.pkl")
print("Done (request-level passive).")
