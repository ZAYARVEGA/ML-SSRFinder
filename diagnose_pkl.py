#!/usr/bin/env python3
"""
Diagnostic script - run from your project directory:
    python3 diagnose_pkl.py
"""
import os, sys, glob, pickle

print("=" * 60)
print("RESPONSE ML MODEL DIAGNOSTIC")
print("=" * 60)

# 1. Where are we?
cwd = os.getcwd()
script_dir = os.path.dirname(os.path.abspath(__file__))
print(f"\n[1] Current working directory : {cwd}")
print(f"    Script location           : {script_dir}")

# 2. Find ALL .pkl files in the project
print(f"\n[2] Searching for .pkl files...")
for search_dir in [script_dir, cwd]:
    pkl_files = glob.glob(os.path.join(search_dir, "*.pkl"))
    print(f"\n    In {search_dir}/")
    if pkl_files:
        for f in sorted(pkl_files):
            size = os.path.getsize(f)
            readable = os.access(f, os.R_OK)
            print(f"      FOUND: {os.path.basename(f)}  ({size:,} bytes, readable={readable})")
    else:
        print(f"      (no .pkl files found)")

    # Also check subdirectories
    pkl_deep = glob.glob(os.path.join(search_dir, "**", "*.pkl"), recursive=True)
    extra = [f for f in pkl_deep if f not in pkl_files]
    if extra:
        print(f"    In subdirectories:")
        for f in sorted(extra):
            print(f"      FOUND: {f}  ({os.path.getsize(f):,} bytes)")

# 3. Check exact expected filenames
print(f"\n[3] Checking exact expected filenames in {script_dir}/")
expected = ['svm_rbf_response.pkl', 'xgboost_response.pkl', 'random_forest_response.pkl']
for name in expected:
    path = os.path.join(script_dir, name)
    exists = os.path.isfile(path)
    if exists:
        size = os.path.getsize(path)
        print(f"    {name}: EXISTS ({size:,} bytes)")
    else:
        print(f"    {name}: MISSING")

# 4. List ALL files in the directory to spot naming issues
print(f"\n[4] All files in {script_dir}/")
try:
    all_files = sorted(os.listdir(script_dir))
    for f in all_files:
        full = os.path.join(script_dir, f)
        if os.path.isfile(full):
            size = os.path.getsize(full)
            marker = " <-- PKL" if f.endswith('.pkl') else ""
            print(f"    {f}  ({size:,} bytes){marker}")
except Exception as e:
    print(f"    ERROR listing directory: {e}")

# 5. Try to actually load each pkl
print(f"\n[5] Attempting to load each model...")
for name in expected:
    path = os.path.join(script_dir, name)
    if not os.path.isfile(path):
        # Also try cwd
        path = os.path.join(cwd, name)
    if not os.path.isfile(path):
        print(f"    {name}: SKIP (file not found)")
        continue
    try:
        with open(path, 'rb') as f:
            data = pickle.load(f)
        keys = list(data.keys())
        print(f"    {name}: LOADED OK (keys: {keys})")
        if 'feature_names' in data:
            print(f"      feature count: {len(data['feature_names'])}")
        if 'metrics' in data:
            print(f"      metrics: {data['metrics']}")
    except Exception as e:
        print(f"    {name}: LOAD FAILED -> {type(e).__name__}: {e}")

# 6. Check neuralforger-response-ml.py exists
print(f"\n[6] Checking neuralforger-response-ml.py...")
rml_path = os.path.join(script_dir, 'neuralforger-response-ml.py')
if os.path.isfile(rml_path):
    size = os.path.getsize(rml_path)
    # Check if it's the updated version (has 'search_dirs')
    with open(rml_path, 'r') as f:
        content = f.read()
    if 'search_dirs' in content:
        print(f"    FOUND (updated version, {size:,} bytes)")
    else:
        print(f"    FOUND but OLD VERSION - needs update! ({size:,} bytes)")
else:
    print(f"    MISSING at {rml_path}")

print(f"\n{'=' * 60}")
print("Copy-paste ALL of this output back to me.")
print("=" * 60)
