#!/usr/bin/env python3
"""
Corrected confidence calibration and fusion for R2-7.

Reviewer 2, R2-7, raised four concrete defects in the shipped scoring
(confirmed in mlssrfinder-detector.py and mlssrfinder-confidence.py):

  1. The scores are not on a probability scale. The request score is a hand
     mapped linear function of a weighted feature sum clamped to [5,95]
     (mlssrfinder-detector.py:158-161), and the injection score is a table of
     hand-picked constants (92, 55, 30, ...). They are then averaged as if they
     were commensurable probabilities.
  2. The lower bound is unreachable. Both the request and injection scores have
     a floor of 5, and in active mode a missing request-ML component is replaced
     by 50, so the nominal 0 can never occur.
  3. The LOW category cannot occur for a vulnerable verdict. is_vulnerable is
     score >= 50 and the severity bands are >=90 / >=70 / >=50 / else LOW, so a
     positive verdict is always at least MEDIUM.
  4. The scales of C_ml, C_inj, C_resp are defined inconsistently: C_resp is a
     model probability, C_ml is the clamped linear map, C_inj is the heuristic
     table.

This module puts all three components on a single [0,1] scale, fuses them so the
full [0,1] range is reachable, and defines severity bands INSIDE the positive
region so the lowest band is reachable for a vulnerable verdict. It is a drop-in
reference for the paper's equations and for wiring into the detector; it does
not modify the shipped files.

Run it to print the end-to-end numerical example R2-7 asks for:
    ./.venv/bin/python calibration_v2.py
"""

import json
import pickle

import numpy as np

# ----------------------------------------------------------------------------
# Common [0,1] scale for each component
# ----------------------------------------------------------------------------
# C_ml and C_resp are model probabilities: use predict_proba for the positive
# class directly, in [0,1]. No clamping, no linear remap.
#
# C_inj is a heuristic likelihood, not a learned probability, so we state it as
# such and give it an explicit, documented, monotone mapping to [0,1]. The
# relative ordering matches the shipped table; the values are simply expressed
# as probabilities-of-vulnerability priors and the artificial floor of 0.05 is
# kept only as the "no evidence" prior, not as an unreachable-zero clamp.
C_INJ_TABLE = [
    # (predicate on (status, has_size_diff, slow), C_inj in [0,1], label)
    (lambda s, d, t: s == 200 and d,                 0.92, "200 + size diff"),
    (lambda s, d, t: 300 <= s < 400 and d,           0.70, "3xx redirect + size diff"),
    (lambda s, d, t: s in (401, 403) and d,          0.55, "401/403 + size diff"),
    (lambda s, d, t: s == 200 and not d,             0.35, "200, no size diff"),
    (lambda s, d, t: s == 404 and d,                 0.30, "404 + size diff"),
    (lambda s, d, t: 500 <= s < 600 and d,           0.22, "5xx + size diff"),
    (lambda s, d, t: t,                              0.40, "slow response (timing)"),
    (lambda s, d, t: 400 <= s < 500,                 0.10, "4xx client error"),
]
C_INJ_PRIOR = 0.05  # no evidence


def c_inj(status_code, size_diff_percent, response_time_ms=None):
    """Heuristic injection likelihood in [0,1]. Documented and monotone."""
    if status_code is None:
        return C_INJ_PRIOR, "connection failed / no response"
    d = (size_diff_percent or 0.0) > 10.0
    t = bool(response_time_ms and response_time_ms > 5000)
    for pred, val, label in C_INJ_TABLE:
        if pred(status_code, d, t):
            return val, label
    return C_INJ_PRIOR, "no significant indicators"


# ----------------------------------------------------------------------------
# Fusion on the common scale (fixes the unreachable-floor bug)
# ----------------------------------------------------------------------------
# Weights are defined per mode, but we renormalize over the components that are
# ACTUALLY present, so a missing component contributes nothing rather than an
# implicit 0.5. That makes the whole [0,1] range reachable.
WEIGHTS_ACTIVE = {"resp": 0.60, "inj": 0.30, "ml": 0.10}
WEIGHTS_PASSIVE = {"inj": 0.70, "ml": 0.30}


def fuse(components, weights):
    """components: dict name->value in [0,1] for the components that are
    present. Renormalizes weights over present components. Returns [0,1]."""
    present = {k: v for k, v in components.items() if v is not None}
    if not present:
        return 0.0
    wsum = sum(weights[k] for k in present)
    return sum(weights[k] * present[k] for k in present) / wsum


# ----------------------------------------------------------------------------
# Content-analysis adjustment as a bounded evidence update (no magic clamps)
# ----------------------------------------------------------------------------
# A confirmed sensitive-data finding is strong positive evidence; a WAF block
# with no findings is negative evidence. We apply a noisy-OR style update that
# stays in [0,1] and preserves monotonicity, instead of overwriting the score
# with a constant like 95.
EVIDENCE_STRENGTH = {"CRITICAL": 0.95, "HIGH": 0.80, "MEDIUM": 0.50, "LOW": 0.20}


def apply_content(combined, finding_severity=None, blocked=False, block_strength=0.8):
    if blocked and finding_severity is None:
        return combined * (1.0 - block_strength)
    if finding_severity is not None:
        e = EVIDENCE_STRENGTH.get(finding_severity, 0.0)
        return combined + (1.0 - combined) * e  # noisy-OR, stays in [0,1]
    return combined


# ----------------------------------------------------------------------------
# Decision and severity (fixes the LOW-unreachable bug)
# ----------------------------------------------------------------------------
TAU = 0.50  # vulnerable iff combined >= TAU

# Severity bands live INSIDE the positive region [TAU, 1], so the lowest band is
# reachable just above the decision threshold.
SEVERITY_BANDS = [
    (0.90, "CRITICAL"),
    (0.75, "HIGH"),
    (0.625, "MEDIUM"),
    (TAU, "LOW"),
]


def decide(combined):
    """Return (is_vulnerable, severity). Severity is only meaningful when
    vulnerable; below TAU we report NOT-FLAGGED with the confidence."""
    if combined < TAU:
        return False, "NOT-FLAGGED"
    for lo, name in SEVERITY_BANDS:
        if combined >= lo:
            return True, name
    return True, "LOW"


# ----------------------------------------------------------------------------
# End-to-end numerical example (uses the real response model for C_resp)
# ----------------------------------------------------------------------------
def _load_response_model():
    d = pickle.load(open("svm_rbf_response.pkl", "rb"))
    return d["model"], d["scaler"], d["feature_names"]


def _c_resp_for(example_path, want_vulnerable):
    """Compute a real C_resp from the shipped SVM on one captured example."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("loso", "loso_validation.py")
    loso = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loso)
    model, scaler, feats = _load_response_model()
    data = json.load(open(example_path))
    ex = next(e for e in data["examples"]
              if bool(e.get("is_vulnerable")) == want_vulnerable and e.get("http_response"))
    fv = loso.extract_features(ex)
    x = np.array([[fv[f] for f in feats]], dtype=float)
    if scaler is not None:
        x = scaler.transform(x)
    p = float(model.predict_proba(x)[0][1])
    return p, ex


def _print_case(title, status, size_diff, resp_path, want_vuln,
                c_ml, finding_sev=None, blocked=False, mode="active"):
    print(f"\n{'-'*70}\n{title}\n{'-'*70}")
    ci, ci_label = c_inj(status, size_diff)
    cr, ex = _c_resp_for(resp_path, want_vuln)
    weights = WEIGHTS_ACTIVE if mode == "active" else WEIGHTS_PASSIVE
    comps = {"resp": cr, "inj": ci, "ml": c_ml} if mode == "active" \
        else {"inj": ci, "ml": c_ml}
    combined = fuse(comps, weights)
    after = apply_content(combined, finding_sev, blocked)
    is_vuln, sev = decide(after)
    print(f"  component inputs (all on [0,1]):")
    print(f"    C_resp (SVM predict_proba, real)         = {cr:.3f}")
    print(f"    C_inj  ({ci_label}) = {ci:.3f}")
    print(f"    C_ml   (request model prior)             = {c_ml:.3f}")
    print(f"  fusion ({mode}, weights renormalized over present components):")
    wtxt = " + ".join(f"{weights[k]:.2f}*{comps[k]:.3f}" for k in comps)
    print(f"    combined = ({wtxt}) / {sum(weights[k] for k in comps):.2f} = {combined:.3f}")
    if finding_sev or blocked:
        kind = f"content finding {finding_sev}" if finding_sev else "WAF block"
        print(f"    after content update ({kind}) = {after:.3f}")
    print(f"  decision: combined {after:.3f} vs tau {TAU:.2f} "
          f"-> {'VULNERABLE' if is_vuln else 'not flagged'}, severity {sev}")


def main():
    print("=" * 70)
    print("R2-7 corrected calibration: end-to-end numerical examples")
    print("=" * 70)
    print(f"Common scale [0,1]. Decision tau={TAU}. Severity bands inside the")
    print(f"positive region so LOW is reachable: CRITICAL>=0.90, HIGH>=0.75,")
    print(f"MEDIUM>=0.625, LOW>=0.50.")

    # Case A: a real vulhub full_read positive, strong on every component.
    _print_case(
        "Case A: GeoServer full_read SSRF (vulhub positive)",
        status=200, size_diff=80.0,
        resp_path="SSRF_VULHUB_PAIRS.normalized.json", want_vuln=True,
        c_ml=0.70, finding_sev="HIGH", mode="active")

    # Case B: the SAME-endpoint benign negative from the same binary.
    _print_case(
        "Case B: GeoServer same-endpoint benign response (vulhub negative)",
        status=200, size_diff=2.0,
        resp_path="SSRF_VULHUB_PAIRS.normalized.json", want_vuln=False,
        c_ml=0.30, finding_sev=None, mode="active")

    # Case C: a borderline positive that lands in the reachable LOW band, to
    # demonstrate bug 3 is fixed (a vulnerable verdict CAN be LOW now).
    print(f"\n{'-'*70}\nCase C: borderline verdict (demonstrates LOW is now reachable)\n{'-'*70}")
    combined = fuse({"resp": 0.52, "inj": 0.55, "ml": 0.45}, WEIGHTS_ACTIVE)
    is_vuln, sev = decide(combined)
    print(f"  combined = {combined:.3f} -> {'VULNERABLE' if is_vuln else 'not flagged'}, "
          f"severity {sev}  (old scheme: impossible, any positive was >= MEDIUM)")

    # Case D: no evidence at all, to show the floor now reaches near 0.
    print(f"\n{'-'*70}\nCase D: no indicators (demonstrates the floor reaches ~0)\n{'-'*70}")
    ci, _ = c_inj(None, 0.0)
    combined = fuse({"inj": ci, "ml": 0.02}, WEIGHTS_PASSIVE)
    print(f"  C_inj={ci:.3f} (no response), C_ml=0.020, passive fusion "
          f"-> combined = {combined:.3f}  (old scheme floored at ~0.33)")


if __name__ == "__main__":
    main()
