#!/usr/bin/env python3
"""
Reproducible evaluation and model regeneration for ML-SSRFinder.
============================================================================
Single entry point that (re)generates the deployed models and prints every
metric reported in the paper, under a leak-free protocol:

  * The StandardScaler for the SVM is fitted INSIDE each cross-validation
    fold (the deployed final model still fits the scaler on all data, which
    is correct for a deployed model).
  * Reported metrics: accuracy, precision, recall, specificity, F1,
    balanced accuracy, MCC, and bootstrap 95% confidence intervals.
  * Majority-class baselines, the majority-vote ensemble, and pairwise
    McNemar tests between models are also reported.

Run:  python3 reproduce_results.py
Exact library versions are printed at the end for reproducibility.
"""
import json, pickle, warnings, itertools, numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import LeaveOneOut, StratifiedKFold, cross_val_score
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, balanced_accuracy_score, matthews_corrcoef)
from scipy.stats import binomtest
from xgboost import XGBClassifier

RNG = 42
np.random.seed(RNG)
BOOT = 5000


def boot_ci(y, yhat):
    n = len(y); idx = np.arange(n)
    accs = [accuracy_score(y[s], yhat[s]) for s in
            (np.random.choice(idx, n, replace=True) for _ in range(BOOT))]
    return tuple(np.percentile(accs, [2.5, 97.5]))


def full_metrics(name, y, yhat):
    cm = confusion_matrix(y, yhat, labels=[0, 1]); tn, fp, fn, tp = cm.ravel()
    lo, hi = boot_ci(y, yhat)
    return dict(name=name, tn=tn, fp=fp, fn=fn, tp=tp,
                acc=accuracy_score(y, yhat),
                prec=precision_score(y, yhat, zero_division=0),
                rec=recall_score(y, yhat, zero_division=0),
                spec=tn / (tn + fp) if (tn + fp) else 0.0,
                f1=f1_score(y, yhat, zero_division=0),
                bal=balanced_accuracy_score(y, yhat),
                mcc=matthews_corrcoef(y, yhat), ci=(lo, hi))


def print_table(rows):
    hdr = (f"{'Model':<22}{'TN':>3}{'FP':>3}{'FN':>3}{'TP':>3}"
           f"{'Acc':>7}{'Prec':>7}{'Rec':>7}{'Spec':>7}{'F1':>7}{'BalAcc':>8}{'MCC':>7}  {'95% CI':>16}")
    print(hdr); print('-' * len(hdr))
    for r in rows:
        print(f"{r['name']:<22}{r['tn']:>3}{r['fp']:>3}{r['fn']:>3}{r['tp']:>3}"
              f"{r['acc']:>7.3f}{r['prec']:>7.3f}{r['rec']:>7.3f}{r['spec']:>7.3f}"
              f"{r['f1']:>7.3f}{r['bal']:>8.3f}{r['mcc']:>7.3f}  [{r['ci'][0]:.3f}, {r['ci'][1]:.3f}]")


def mcnemar(a, b, y):
    ca = (a == y).astype(int); cb = (b == y).astype(int)
    n01 = int(((ca == 0) & (cb == 1)).sum()); n10 = int(((ca == 1) & (cb == 0)).sum())
    p = binomtest(min(n01, n10), n01 + n10, 0.5).pvalue if (n01 + n10) else 1.0
    return n01, n10, p


# ============================ RESPONSE CORPUS ============================
raw = json.load(open('response_dataset_final.json'))
examples = [e for e in raw['examples'] if e.get('ssrf_type') not in ['blind_oob']]

def resp_features(example):
    r = example['http_response']
    status = r.get('status_code') or 0; size = r.get('response_size_bytes') or 0
    rt = r.get('response_time_ms') or 0; server = (r.get('server_header') or '').lower()
    ct = (r.get('content_type') or '').lower(); struct = (r.get('body_structure') or '').lower()
    bej = int(r.get('body_has_error_json', False))
    to = r.get('timing_open_port_ms') or 0; tc = r.get('timing_closed_port_ms') or 0
    un = r.get('unusual_headers') or []
    return {
        'status_is_200': int(status == 200), 'status_is_400': int(status == 400),
        'status_is_403': int(status == 403), 'status_is_404': int(status == 404),
        'status_is_502': int(status == 502), 'status_4xx': int(400 <= status < 500),
        'status_5xx': int(500 <= status < 600), 'size_small': int(0 < size < 500),
        'size_medium': int(500 <= size < 5000), 'size_large': int(size >= 5000),
        'time_slow': int(rt >= 1000), 'timing_ratio': (to / tc) if tc > 0 else 0,
        'server_ec2ws': int('ec2ws' in server), 'server_istio': int('istio' in server),
        'server_cloud': int(any(x in server for x in ['cloudflare', 'github', 'amazons3'])),
        'ct_text_plain': int(ct.strip().startswith('text/plain')), 'ct_json': int('json' in ct),
        'ct_xml': int('xml' in ct), 'ct_mismatch': int(ct.strip().startswith('text/plain') and not bej),
        'body_aws_meta': int(r.get('body_has_aws_metadata', False)),
        'body_creds': int(r.get('body_has_credentials', False)),
        'body_oob_echo': int(r.get('body_has_oob_echo', False)), 'body_error_json': bej,
        'body_bearer': int(r.get('body_has_bearer_token', False)),
        'body_internal_info': int(r.get('body_has_internal_service_info', False)),
        'struct_metadata': int('metadata_listing' in struct),
        'struct_creds_json': int('credentials_json' in struct),
        'struct_error': int('error' in struct),
        'is_timing_diff': int(r.get('is_timing_differential', False)),
        'is_status_diff': int(r.get('is_status_differential', False)),
        'is_content_diff': int(r.get('is_content_differential', False)),
        'has_auth_header': int(any('auth' in str(h).lower() for h in un)),
        'has_forwarded': int(any('forward' in str(h).lower() for h in un)),
    }

Xr = pd.DataFrame([resp_features(e) for e in examples])
yr = np.array([1 if e['is_vulnerable'] else 0 for e in examples])
resp_feat_names = list(Xr.columns); Xrv = Xr.values; nR = len(yr)

MODELS = {
    'svm_rbf': ('SVM-RBF', True, lambda: SVC(kernel='rbf', C=1.0, gamma='scale',
        probability=True, class_weight='balanced', random_state=RNG)),
    'xgboost': ('XGBoost', False, lambda: XGBClassifier(n_estimators=100, max_depth=3,
        learning_rate=0.1, subsample=0.8, colsample_bytree=0.8, reg_alpha=0.1, reg_lambda=1.0,
        use_label_encoder=False, eval_metric='logloss', random_state=RNG, verbosity=0)),
    'random_forest': ('Random Forest', False, lambda: RandomForestClassifier(n_estimators=200,
        max_depth=4, min_samples_leaf=2, max_features='sqrt', bootstrap=True,
        random_state=RNG, class_weight='balanced')),
}
loo = LeaveOneOut(); skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RNG)
pred = {k: np.zeros(nR, int) for k in MODELS}
for tr, te in loo.split(Xrv):
    for k, (_, scale, ctor) in MODELS.items():
        if scale:
            sc = StandardScaler(); Xt = sc.fit_transform(Xrv[tr]); Xe = sc.transform(Xrv[te])
        else:
            Xt, Xe = Xrv[tr], Xrv[te]
        m = ctor(); m.fit(Xt, yr[tr]); pred[k][te[0]] = int(m.predict(Xe)[0])
ens = ((pred['svm_rbf'] + pred['xgboost'] + pred['random_forest']) >= 2).astype(int)

def skf_metrics(k):
    _, scale, ctor = MODELS[k]
    est = Pipeline([('sc', StandardScaler()), ('clf', ctor())]) if scale else ctor()
    return {m: cross_val_score(est, Xrv, yr, cv=skf, scoring=m).mean()
            for m in ['accuracy', 'precision', 'recall', 'f1']}

print("=" * 70)
print("RESPONSE CORPUS (n=28, 15 vulnerable / 13 benign) — leave-one-out, leak-free")
print("=" * 70)
rows = [full_metrics(MODELS[k][0], yr, pred[k]) for k in MODELS] + [full_metrics('Ensemble (majority)', yr, ens)]
print_table(rows)
print(f"\nMajority-class baseline accuracy: {max(yr.mean(), 1 - yr.mean()):.3f}")
print("\nStratified 5-fold (scaler fitted in-fold via Pipeline):")
for k in MODELS:
    s = skf_metrics(k)
    print(f"  {MODELS[k][0]:<15} acc={s['accuracy']:.4f} prec={s['precision']:.4f} rec={s['recall']:.4f} f1={s['f1']:.4f}")
print("\nPairwise McNemar (leave-one-out predictions):")
for a, b in [('svm_rbf', 'xgboost'), ('svm_rbf', 'random_forest'), ('xgboost', 'random_forest')]:
    n01, n10, p = mcnemar(pred[a], pred[b], yr)
    print(f"  {MODELS[a][0]} vs {MODELS[b][0]}: only-{MODELS[b][0]}-correct={n01}, only-{MODELS[a][0]}-correct={n10}, p={p:.3f}")
n01, n10, p = mcnemar(ens, pred['svm_rbf'], yr)
print(f"  Ensemble vs SVM-RBF: only-SVM-correct={n01}, only-Ensemble-correct={n10}, p={p:.3f}")

# --- Regenerate deployed response models (final fit on all data) ---
print("\nRegenerating response model files (final fit on all data)...")
for k, (label, scale, ctor) in MODELS.items():
    if scale:
        sc = StandardScaler(); Xall = sc.fit_transform(Xrv)
    else:
        sc = None; Xall = Xrv
    model = ctor(); model.fit(Xall, yr)
    r = full_metrics(label, yr, pred[k]); s = skf_metrics(k)
    payload = {
        'model': model, 'scaler': sc, 'feature_names': resp_feat_names, 'needs_scaling': scale,
        'metrics': {'loo_accuracy': r['acc'], 'loo_precision': r['prec'], 'loo_recall': r['rec'],
                    'loo_specificity': r['spec'], 'loo_f1': r['f1'], 'loo_balanced_accuracy': r['bal'],
                    'loo_mcc': r['mcc'], 'loo_acc_ci95': list(r['ci']),
                    'skf_accuracy': s['accuracy'], 'skf_f1': s['f1']},
        'training_info': {'n_samples': nR, 'n_vulnerable': int(yr.sum()), 'n_benign': int(nR - yr.sum()),
                          'cv_method': 'LeaveOneOut (scaler fitted in-fold) + StratifiedKFold-5',
                          'dataset': 'response_dataset_final.json (blind_oob excluded)'},
    }
    fname = k + '_response.pkl'
    with open(fname, 'wb') as f: pickle.dump(payload, f)
    print(f"  saved {fname}  (LOO acc {r['acc']:.3f})")

# ============================ REQUEST CORPUS ============================
print("\n" + "=" * 70)
print("REQUEST CORPUS (n=40, 30 vulnerable / 10 benign) — leave-one-out")
print("=" * 70)
import importlib.util, sys
spec = importlib.util.spec_from_file_location('det', 'mlssrfinder-detector.py')
det = importlib.util.module_from_spec(spec); sys.modules['det'] = det; spec.loader.exec_module(det)
req = json.load(open('BALANCED_DATASET_40_EXAMPLES.json'))['examples']
def req_row(ex):
    q = ex['http_request']; url = q.get('url') or ''; method = q.get('method') or 'GET'
    body = q.get('body') or {}; inj = q.get('injection_details') or {}
    param = (body.get('parameter_name') or '') or (inj.get('vulnerable_parameter') or '')
    h = q.get('headers') or {}; auth = bool(h.get('Authorization')) or bool(inj.get('requires_authentication'))
    return {kk: int(vv) for kk, vv in det.extract_features(url, param, method, auth).items()}
Xq = pd.DataFrame([req_row(e) for e in req]); yq = np.array([1 if e['is_vulnerable'] else 0 for e in req])
req_names = list(Xq.columns); Xqv = Xq.values
pq = np.zeros(len(yq), int)
for tr, te in loo.split(Xqv):
    m = MODELS['xgboost'][2](); m.fit(Xqv[tr], yq[tr]); pq[te[0]] = int(m.predict(Xqv[te])[0])
print_table([full_metrics('Passive XGBoost', yq, pq)])
print(f"\nMajority-class baseline accuracy: {max(yq.mean(), 1 - yq.mean()):.3f}")

import sklearn, xgboost, scipy
print("\n" + "=" * 70)
print(f"Library versions: python {sys.version.split()[0]}, numpy {np.__version__}, "
      f"pandas {pd.__version__}, scikit-learn {sklearn.__version__}, "
      f"xgboost {xgboost.__version__}, scipy {scipy.__version__}")
print("=" * 70)
