#!/usr/bin/env python3
"""
Retrain Response ML Models v3

Expanded features (41 total, up from 35):
  NEW: body_has_system_file, body_has_db_config, body_has_private_key,
       body_has_waf_block, body_has_env_config, body_has_gcp_metadata

Fixes: XGBoost probability calibration (was 0% or 100%)
"""

import pickle
import numpy as np
import pandas as pd
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import LeaveOneOut, cross_val_score
from sklearn.calibration import CalibratedClassifierCV
import warnings
warnings.filterwarnings('ignore')

try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("[!] xgboost not available, using GradientBoosting as fallback")


def extract_features_from_example(ex):
    features = {}
    status = ex.get('status_code')
    features['status_is_200'] = 1 if status == 200 else 0
    features['status_is_redirect'] = 1 if status and 300 <= status < 400 else 0
    features['status_is_error'] = 1 if status and status >= 400 else 0
    features['status_is_server_error'] = 1 if status and 500 <= status < 600 else 0
    size = ex.get('response_size_bytes') or 0
    features['response_size_bytes'] = size
    features['size_is_zero'] = 1 if size == 0 else 0
    features['size_is_small'] = 1 if 0 < size <= 500 else 0
    features['size_is_medium'] = 1 if 500 < size <= 5000 else 0
    features['size_is_large'] = 1 if size > 5000 else 0
    timing = ex.get('response_time_ms') or 0
    features['response_time_ms'] = timing
    features['timing_is_fast'] = 1 if timing < 500 else 0
    features['timing_is_slow'] = 1 if timing > 3000 else 0
    ct = (ex.get('content_type') or '').lower()
    features['ct_is_json'] = 1 if 'json' in ct else 0
    features['ct_is_html'] = 1 if 'html' in ct else 0
    features['ct_is_xml'] = 1 if 'xml' in ct else 0
    features['ct_is_text'] = 1 if ct.startswith('text/plain') else 0
    features['ct_is_image'] = 1 if 'image' in ct else 0
    features['has_server_header'] = 1 if ex.get('server_header') else 0
    features['body_has_aws_metadata'] = 1 if ex.get('body_has_aws_metadata') else 0
    features['body_has_credentials'] = 1 if ex.get('body_has_credentials') else 0
    features['body_has_oob_echo'] = 1 if ex.get('body_has_oob_echo') else 0
    features['body_has_error_json'] = 1 if ex.get('body_has_error_json') else 0
    features['body_has_bearer_token'] = 1 if ex.get('body_has_bearer_token') else 0
    features['body_has_internal_service_info'] = 1 if ex.get('body_has_internal_service_info') else 0
    features['body_has_system_file'] = 1 if ex.get('body_has_system_file') else 0
    features['body_has_db_config'] = 1 if ex.get('body_has_db_config') else 0
    features['body_has_private_key'] = 1 if ex.get('body_has_private_key') else 0
    features['body_has_waf_block'] = 1 if ex.get('body_has_waf_block') else 0
    features['body_has_env_config'] = 1 if ex.get('body_has_env_config') else 0
    features['body_has_gcp_metadata'] = 1 if ex.get('body_has_gcp_metadata') else 0
    unusual = ex.get('unusual_headers') or []
    features['unusual_header_count'] = len(unusual) if isinstance(unusual, list) else (1 if unusual else 0)
    features['has_unusual_headers'] = 1 if features['unusual_header_count'] > 0 else 0
    structure = ex.get('body_structure', 'empty')
    for cat in ['metadata_listing', 'credentials_json', 'error_json',
                'html_public_page', 'success_json', 'empty']:
        features[f'structure_{cat}'] = 1 if structure == cat else 0
    features['is_timing_differential'] = 1 if ex.get('is_timing_differential') else 0
    features['is_status_differential'] = 1 if ex.get('is_status_differential') else 0
    features['is_content_differential'] = 1 if ex.get('is_content_differential') else 0
    return features

def _base(rng, **ov):
    ex = dict(label=0, status_code=200, response_size_bytes=5000, response_time_ms=50,
        content_type='text/html', server_header='Apache',
        body_has_aws_metadata=False, body_has_credentials=False, body_has_oob_echo=False,
        body_has_error_json=False, body_has_bearer_token=False, body_has_internal_service_info=False,
        body_has_system_file=False, body_has_db_config=False, body_has_private_key=False,
        body_has_waf_block=False, body_has_env_config=False, body_has_gcp_metadata=False,
        unusual_headers=[], body_structure='html_public_page',
        is_timing_differential=False, is_status_differential=False, is_content_differential=False)
    ex.update(ov)
    return ex

def generate_training_data():
    examples = []
    rng = np.random.RandomState(42)

    # POSITIVE: AWS creds in JSON
    for _ in range(15):
        examples.append(_base(rng, label=1, response_size_bytes=rng.randint(300,800),
            response_time_ms=rng.uniform(50,300), content_type='application/json',
            body_has_aws_metadata=rng.random()>0.3, body_has_credentials=True,
            body_has_bearer_token=rng.random()>0.6, body_has_internal_service_info=rng.random()>0.5,
            unusual_headers=['X-Amz-Request-Id: abc'] if rng.random()>0.3 else [],
            body_structure='credentials_json', is_content_differential=True))

    # POSITIVE: AWS creds in HTML
    for _ in range(20):
        examples.append(_base(rng, label=1, response_size_bytes=rng.randint(8000,15000),
            response_time_ms=rng.uniform(2,50), body_has_aws_metadata=rng.random()>0.3,
            body_has_credentials=True, body_has_internal_service_info=rng.random()>0.4,
            is_content_differential=True))

    # POSITIVE: AWS metadata raw
    for _ in range(12):
        examples.append(_base(rng, label=1, response_size_bytes=rng.randint(100,2000),
            response_time_ms=rng.uniform(20,200), content_type='text/plain',
            server_header=rng.choice(['EC2ws',None]), body_has_aws_metadata=True,
            body_has_credentials=rng.random()>0.7, body_structure='metadata_listing',
            unusual_headers=['X-Amz-Request-Id: x'] if rng.random()>0.4 else [],
            is_content_differential=True))

    # POSITIVE: AWS metadata in HTML
    for _ in range(20):
        examples.append(_base(rng, label=1, response_size_bytes=rng.randint(8000,15000),
            response_time_ms=rng.uniform(2,50), body_has_aws_metadata=True,
            body_has_credentials=rng.random()>0.6, body_has_internal_service_info=rng.random()>0.4,
            is_content_differential=True))

    # POSITIVE: /etc/passwd raw
    for _ in range(12):
        examples.append(_base(rng, label=1, response_size_bytes=rng.randint(200,3000),
            response_time_ms=rng.uniform(2,100), content_type='text/plain',
            body_has_system_file=True, body_has_internal_service_info=True,
            body_structure='metadata_listing', is_content_differential=True))

    # POSITIVE: /etc/passwd in HTML
    for _ in range(15):
        examples.append(_base(rng, label=1, response_size_bytes=rng.randint(8000,15000),
            response_time_ms=rng.uniform(2,50), body_has_system_file=True,
            body_has_internal_service_info=rng.random()>0.5, is_content_differential=True))

    # POSITIVE: DB config raw
    for _ in range(10):
        examples.append(_base(rng, label=1, response_size_bytes=rng.randint(100,3000),
            response_time_ms=rng.uniform(2,150), content_type=rng.choice(['text/plain','application/json']),
            body_has_db_config=True, body_has_credentials=rng.random()>0.5,
            body_has_internal_service_info=True, body_structure='credentials_json',
            is_content_differential=True))

    # POSITIVE: DB config in HTML (your lab /user-data)
    for _ in range(15):
        examples.append(_base(rng, label=1, response_size_bytes=rng.randint(8000,15000),
            response_time_ms=rng.uniform(2,50), body_has_db_config=True,
            body_has_credentials=rng.random()>0.5, body_has_internal_service_info=rng.random()>0.4,
            is_content_differential=True))

    # POSITIVE: Private keys
    for _ in range(10):
        ct = rng.choice(['text/plain','text/html'])
        examples.append(_base(rng, label=1, response_size_bytes=rng.randint(8000,15000) if 'html' in ct else rng.randint(500,3000),
            response_time_ms=rng.uniform(2,100), content_type=ct,
            body_has_private_key=True, body_has_internal_service_info=True,
            body_structure='html_public_page' if 'html' in ct else 'metadata_listing',
            is_content_differential=True))

    # POSITIVE: .env config
    for _ in range(10):
        ct = rng.choice(['text/plain','text/html'])
        examples.append(_base(rng, label=1, response_size_bytes=rng.randint(8000,15000) if 'html' in ct else rng.randint(200,2000),
            response_time_ms=rng.uniform(2,100), content_type=ct,
            body_has_env_config=True, body_has_credentials=True, body_has_internal_service_info=True,
            body_structure='html_public_page' if 'html' in ct else 'metadata_listing',
            is_content_differential=True))

    # POSITIVE: GCP metadata
    for _ in range(10):
        ct = rng.choice(['application/json','text/plain','text/html'])
        examples.append(_base(rng, label=1, response_size_bytes=rng.randint(8000,15000) if 'html' in ct else rng.randint(200,5000),
            response_time_ms=rng.uniform(30,250), content_type=ct,
            body_has_gcp_metadata=True, body_has_credentials=rng.random()>0.5,
            body_has_bearer_token=rng.random()>0.6, body_has_internal_service_info=True,
            unusual_headers=['Metadata-Flavor: Google'] if rng.random()>0.3 else [],
            body_structure='html_public_page' if 'html' in ct else 'success_json',
            is_content_differential=True))

    # POSITIVE: Internal services
    for _ in range(10):
        examples.append(_base(rng, label=1, response_size_bytes=rng.randint(5000,50000),
            response_time_ms=rng.uniform(10,200), body_has_internal_service_info=True,
            unusual_headers=['X-Forwarded-For: 10.0.0.1'] if rng.random()>0.5 else [],
            is_content_differential=True))

    # POSITIVE: Error-based SSRF
    for _ in range(8):
        examples.append(_base(rng, label=1, status_code=rng.choice([200,500,502,504]),
            response_size_bytes=rng.randint(200,1500), response_time_ms=rng.uniform(100,5000),
            content_type='application/json', body_has_error_json=True,
            body_has_internal_service_info=rng.random()>0.5, body_structure='error_json',
            is_timing_differential=rng.random()>0.4, is_status_differential=rng.random()>0.4,
            is_content_differential=True))

    # POSITIVE: OOB/blind SSRF
    for _ in range(5):
        examples.append(_base(rng, label=1, response_size_bytes=rng.randint(50,500),
            response_time_ms=rng.uniform(3000,15000), content_type='application/json',
            body_has_oob_echo=rng.random()>0.5, body_structure='success_json',
            is_timing_differential=True))

    # NEGATIVE: WAF blocked
    for _ in range(35):
        examples.append(_base(rng, label=0, response_size_bytes=rng.randint(5000,15000),
            response_time_ms=rng.uniform(2,50), body_has_waf_block=True))

    # NEGATIVE: Normal HTML
    for _ in range(30):
        examples.append(_base(rng, label=0, response_size_bytes=rng.randint(8000,30000),
            response_time_ms=rng.uniform(10,200)))

    # NEGATIVE: Normal JSON
    for _ in range(25):
        examples.append(_base(rng, label=0, response_size_bytes=rng.randint(100,5000),
            response_time_ms=rng.uniform(20,300), content_type='application/json',
            body_structure='success_json'))

    # NEGATIVE: 404/error
    for _ in range(15):
        examples.append(_base(rng, label=0, status_code=rng.choice([404,400,405,422]),
            response_size_bytes=rng.randint(200,5000), response_time_ms=rng.uniform(5,100),
            body_has_error_json=rng.random()>0.5, body_structure=rng.choice(['error_json','html_public_page'])))

    # NEGATIVE: Server errors
    for _ in range(10):
        examples.append(_base(rng, label=0, status_code=rng.choice([500,502,503,504]),
            response_size_bytes=rng.randint(100,2000), response_time_ms=rng.uniform(50,1000),
            body_has_error_json=True, body_structure='error_json'))

    # NEGATIVE: Timeouts
    for _ in range(10):
        examples.append(_base(rng, label=0, status_code=None, response_size_bytes=0,
            response_time_ms=rng.uniform(5000,30000), content_type='', server_header=None,
            body_structure='empty'))

    # NEGATIVE: Tricky - large HTML with error but no sensitive content
    for _ in range(10):
        examples.append(_base(rng, label=0, response_size_bytes=rng.randint(8000,15000),
            response_time_ms=rng.uniform(2,50), body_has_error_json=True))

    rng.shuffle(examples)
    return examples

print("Generating dataset...")
examples = generate_training_data()
positives = sum(1 for ex in examples if ex['label'] == 1)
negatives = len(examples) - positives
print(f"Dataset: {len(examples)} ({positives} pos, {negatives} neg)")

feature_dicts = [extract_features_from_example(ex) for ex in examples]
FEATURE_NAMES = sorted(feature_dicts[0].keys())
print(f"Features: {len(FEATURE_NAMES)}")

X = pd.DataFrame(feature_dicts)[FEATURE_NAMES]
y = np.array([ex['label'] for ex in examples])
loo = LeaveOneOut()

# SVM-RBF
print("\nSVM-RBF...")
scaler = StandardScaler()
X_s = scaler.fit_transform(X)
svm = SVC(kernel='rbf', C=10, gamma='scale', probability=True, random_state=42)
svm.fit(X_s, y)
svm_acc = cross_val_score(svm, X_s, y, cv=loo).mean()
print(f"  LOO: {svm_acc*100:.1f}%")
pickle.dump({'model': svm, 'scaler': scaler, 'feature_names': FEATURE_NAMES,
    'needs_scaling': True, 'metrics': {'loo_accuracy': round(svm_acc,4)},
    'training_info': {'dataset_size': len(examples)}}, open('svm_rbf_response.pkl','wb'))

# XGBoost (calibrated)
print("XGBoost (calibrated)...")
if HAS_XGBOOST:
    base = XGBClassifier(n_estimators=100, max_depth=4, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8, min_child_weight=3,
        use_label_encoder=False, eval_metric='logloss', random_state=42)
else:
    base = GradientBoostingClassifier(n_estimators=100, max_depth=4,
        learning_rate=0.1, subsample=0.8, min_samples_leaf=5, random_state=42)
xgb = CalibratedClassifierCV(base, cv=5, method='isotonic')
xgb.fit(X.values, y)
xgb_acc = cross_val_score(xgb, X.values, y, cv=loo).mean()
print(f"  LOO: {xgb_acc*100:.1f}%")
pickle.dump({'model': xgb, 'scaler': None, 'feature_names': FEATURE_NAMES,
    'needs_scaling': False, 'metrics': {'loo_accuracy': round(xgb_acc,4)},
    'training_info': {'dataset_size': len(examples), 'calibrated': True}},
    open('xgboost_response.pkl','wb'))

# Random Forest
print("Random Forest...")
rf = RandomForestClassifier(n_estimators=300, max_depth=8, min_samples_split=3,
    min_samples_leaf=2, random_state=42)
rf.fit(X.values, y)
rf_acc = cross_val_score(rf, X.values, y, cv=loo).mean()
print(f"  LOO: {rf_acc*100:.1f}%")
pickle.dump({'model': rf, 'scaler': None, 'feature_names': FEATURE_NAMES,
    'needs_scaling': False, 'metrics': {'loo_accuracy': round(rf_acc,4)},
    'training_info': {'dataset_size': len(examples)}}, open('random_forest_response.pkl','wb'))

# VERIFICATION
print(f"\n{'='*60}\nVERIFICATION\n{'='*60}")

def test(label, ex):
    feats = extract_features_from_example(ex)
    row = pd.DataFrame([feats])[FEATURE_NAMES]
    print(f"\n  {label}")
    for name, mdl, sc in [('svm_rbf',svm,True),('xgboost',xgb,False),('random_forest',rf,False)]:
        Xt = scaler.transform(row) if sc else row.values
        p = mdl.predict(Xt)[0]
        prob = mdl.predict_proba(Xt)[0][1]*100
        print(f"    {name:<15}: {prob:5.1f}% ({'POS' if p else 'NEG'})")

test("LAB: /meta-data/ (HTML+metadata)", _base(None, label=1,
    response_size_bytes=10676, response_time_ms=2, body_has_aws_metadata=True,
    is_content_differential=True))
test("LAB: /iam/creds (HTML+creds+meta)", _base(None, label=1,
    response_size_bytes=11068, response_time_ms=3, body_has_aws_metadata=True,
    body_has_credentials=True, body_has_internal_service_info=True, is_content_differential=True))
test("LAB: /user-data (HTML+db_password)", _base(None, label=1,
    response_size_bytes=10562, response_time_ms=3, body_has_db_config=True,
    body_has_internal_service_info=True, is_content_differential=True))
test("LAB: file:///etc/passwd (HTML)", _base(None, label=1,
    response_size_bytes=12164, response_time_ms=2, body_has_system_file=True,
    body_has_internal_service_info=True, is_content_differential=True))
test("WAF BLOCKED", _base(None, label=0,
    response_size_bytes=10500, response_time_ms=3, body_has_waf_block=True))
test("Normal HTML", _base(None, label=0,
    response_size_bytes=9488, response_time_ms=3))
test("Normal JSON API", _base(None, label=0,
    response_size_bytes=2000, response_time_ms=50, content_type='application/json',
    body_structure='success_json'))

print(f"\n{'='*60}")
print(f"SVM: {svm_acc*100:.1f}% | XGB: {xgb_acc*100:.1f}% | RF: {rf_acc*100:.1f}%")
print(f"Features: {len(FEATURE_NAMES)} | Dataset: {len(examples)}")
print(f"{'='*60}")
