#!/usr/bin/env python3
"""
ML-SSRFinder - Confidence Scoring Engine (Extension)

Extends SSRFinder's confidence_calculator with combined ML+injection
scoring. Uses SSRFinder's base confidence logic and adds weighted
ML integration for unified vulnerability assessment.
"""

from typing import Tuple, Optional, Dict, Any

# Import SSRFinder's base confidence logic
from confidence_calculator import calculate_confidence as ssrf_calculate_confidence

# Weight constants — passive mode (unchanged)
ML_WEIGHT = 0.30
INJECTION_WEIGHT = 0.70

# Weight constants — active mode (when --response-ml is active)
RESPONSE_ML_WEIGHT_ACTIVE = 0.60    # response ML is most reliable in active mode
INJECTION_WEIGHT_ACTIVE   = 0.30    # status/size diff still relevant
REQUEST_ML_WEIGHT_ACTIVE  = 0.10    # request ML becomes a minor prior


class ConfidenceResult:
    """Structured confidence assessment result."""

    def __init__(
        self,
        injection_confidence: float,
        injection_level: str,
        injection_reason: str,
        ml_confidence: Optional[float] = None,
        combined_confidence: Optional[float] = None,
        response_ml_confidence: Optional[float] = None,
        response_ml_verdicts: Optional[list] = None,
        response_ml_positive: Optional[bool] = None,
    ):
        self.injection_confidence = injection_confidence
        self.injection_level = injection_level
        self.injection_reason = injection_reason
        self.ml_confidence = ml_confidence
        self.combined_confidence = combined_confidence
        self.response_ml_confidence = response_ml_confidence
        self.response_ml_verdicts = response_ml_verdicts
        self.response_ml_positive = response_ml_positive
        self.content_analysis = None          # NEW: ContentAnalysis object
        self.content_blocked = False           # NEW: was request blocked by WAF?
        self.content_findings_count = 0        # NEW: number of sensitive findings

    @property
    def severity(self) -> str:
        """Determine severity label from combined or injection confidence."""
        score = self.combined_confidence if self.combined_confidence is not None else self.injection_confidence
        if score >= 90.0:
            return "CRITICAL"
        if score >= 70.0:
            return "HIGH"
        if score >= 50.0:
            return "MEDIUM"
        if score >= 25.0:
            return "LOW"
        return "INFO"

    @property
    def is_vulnerable(self) -> bool:
        """Whether the combined assessment indicates vulnerability."""
        score = self.combined_confidence if self.combined_confidence is not None else self.injection_confidence
        return score >= 50.0

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "injection_confidence": round(self.injection_confidence, 1),
            "injection_level": self.injection_level,
            "injection_reason": self.injection_reason,
            "ml_confidence": round(self.ml_confidence, 1) if self.ml_confidence is not None else None,
            "combined_confidence": round(self.combined_confidence, 1) if self.combined_confidence is not None else None,
            "response_ml_confidence": round(self.response_ml_confidence, 1) if self.response_ml_confidence is not None else None,
            "response_ml_positive": self.response_ml_positive,
            "severity": self.severity,
            "is_vulnerable": self.is_vulnerable,
        }
        return result


# Extended injection confidence mapping with numeric scores
# Maps (status_code_category, has_size_diff) -> (numeric_confidence, level, reason)
_CONFIDENCE_MAP = {
    (200, True):   (92.0, "HIGH",        "Status 200 with significant response size difference"),
    (200, False):  (35.0, "LOW",         "Status 200 but no significant response difference"),
    (201, True):   (78.0, "MEDIUM-HIGH", "Status 201 with response size difference"),
    (202, True):   (75.0, "MEDIUM-HIGH", "Status 202 with response size difference"),
    (301, True):   (70.0, "MEDIUM-HIGH", "Redirect (301) with size difference"),
    (302, True):   (72.0, "MEDIUM-HIGH", "Redirect (302) with size difference"),
    (303, True):   (68.0, "MEDIUM",      "Redirect (303) with size difference"),
    (307, True):   (72.0, "MEDIUM-HIGH", "Redirect (307) with size difference"),
    (308, True):   (72.0, "MEDIUM-HIGH", "Redirect (308) with size difference"),
    (401, True):   (55.0, "MEDIUM",      "Access denied (401) - server processed internal request"),
    (403, True):   (55.0, "MEDIUM",      "Forbidden (403) - server processed internal request"),
    (404, True):   (30.0, "LOW-MEDIUM",  "Not found (404) - possible internal connection"),
    (500, True):   (25.0, "LOW",         "Server error (500) - possible failed SSRF attempt"),
    (502, True):   (28.0, "LOW",         "Bad gateway (502) - possible backend SSRF interaction"),
    (503, True):   (20.0, "LOW",         "Service unavailable (503)"),
    (504, True):   (22.0, "LOW",         "Gateway timeout (504) - possible slow SSRF target"),
}


def calculate_injection_confidence(
    status_code: Optional[int],
    size_diff_percent: float,
    response_time_ms: Optional[float] = None,
) -> Tuple[float, str, str]:
    """
    Calculate confidence from injection test response characteristics.

    Enhanced version that provides numeric confidence scores for ML integration.

    Args:
        status_code: HTTP response status code (None if connection failed).
        size_diff_percent: Percentage difference from baseline response size.
        response_time_ms: Response time in milliseconds (optional).

    Returns:
        Tuple of (numeric_confidence, level_string, reason_string).
    """
    if status_code is None:
        return 5.0, "NONE", "Connection failed - target unreachable"

    has_diff = size_diff_percent > 10.0

    # Check exact match first
    key = (status_code, has_diff)
    if key in _CONFIDENCE_MAP:
        return _CONFIDENCE_MAP[key]

    # Category fallbacks
    if 200 <= status_code < 300 and has_diff:
        return 70.0, "MEDIUM-HIGH", f"Success status ({status_code}) with size difference"
    if 300 <= status_code < 400 and has_diff:
        return 60.0, "MEDIUM", f"Redirect status ({status_code}) with size difference"
    if 400 <= status_code < 500:
        return 10.0, "VERY-LOW", f"Client error ({status_code}) - likely false positive"
    if 500 <= status_code < 600 and has_diff:
        return 22.0, "LOW", f"Server error ({status_code}) with size difference"

    # Time-based bonus
    if response_time_ms and response_time_ms > 5000:
        return 40.0, "LOW-MEDIUM", f"Significant response delay ({response_time_ms:.0f}ms)"

    return 5.0, "NONE", "No significant indicators detected"


def calculate_combined_confidence(
    injection_confidence: float,
    ml_confidence: Optional[float] = None,
    ml_weight: float = ML_WEIGHT,
    injection_weight: float = INJECTION_WEIGHT,
) -> float:
    """
    Compute weighted combined confidence from ML and injection scores.

    Args:
        injection_confidence: Injection test confidence (0-100).
        ml_confidence: ML prediction confidence (0-100), or None.
        ml_weight: Weight for ML score (default 0.30).
        injection_weight: Weight for injection score (default 0.70).

    Returns:
        Combined confidence score (0-100).
    """
    if ml_confidence is None:
        return injection_confidence

    combined = (ml_confidence * ml_weight) + (injection_confidence * injection_weight)
    return min(100.0, max(0.0, combined))


def calculate_combined_confidence_active(
    injection_confidence: float,
    request_ml_confidence: Optional[float],
    response_ml_confidence: float,
) -> float:
    """
    Active mode: response ML is the dominant signal.

    Used when --response-ml flag is active. Weights:
        response ML (60%) + injection (30%) + request ML (10%)

    Args:
        injection_confidence: Injection test confidence (0-100).
        request_ml_confidence: Request-based ML confidence (0-100), or None.
        response_ml_confidence: Response-based ML confidence (0-100).

    Returns:
        Combined confidence score (0-100).
    """
    req_ml = request_ml_confidence if request_ml_confidence is not None else 50.0
    combined = (
        response_ml_confidence * RESPONSE_ML_WEIGHT_ACTIVE +
        injection_confidence   * INJECTION_WEIGHT_ACTIVE   +
        req_ml                 * REQUEST_ML_WEIGHT_ACTIVE
    )
    return min(100.0, max(0.0, combined))


def build_confidence_result(
    status_code: Optional[int],
    size_diff_percent: float,
    response_time_ms: Optional[float] = None,
    ml_confidence: Optional[float] = None,
    response_ml_result=None,
    content_analysis=None,
) -> ConfidenceResult:
    """
    Build a complete confidence assessment.

    Combines injection confidence calculation with optional ML confidence.
    When response_ml_result is provided (active mode), uses the active
    weighting formula where response ML is dominant.
    When content_analysis is provided, applies content-based adjustments
    (blocks lower confidence, sensitive data boosts it).

    Args:
        status_code: HTTP status code.
        size_diff_percent: Response size difference percentage.
        response_time_ms: Response time in milliseconds.
        ml_confidence: Request-based ML prediction confidence.
        response_ml_result: ResponseMLResult object (active mode).
        content_analysis: ContentAnalysis object from body scanning.

    Returns:
        ConfidenceResult with all scores populated.
    """
    inj_conf, inj_level, inj_reason = calculate_injection_confidence(
        status_code, size_diff_percent, response_time_ms,
    )

    response_ml_confidence = None
    response_ml_verdicts = None
    response_ml_positive = None
    combined = None

    if response_ml_result is not None:
        # Active mode: response ML is the dominant signal. Use the primary
        # decision (default: the SVM-RBF model) rather than the ensemble, which
        # does not improve on the best single model on the response corpus.
        # Fall back to the ensemble fields for backward compatibility.
        response_ml_confidence = getattr(
            response_ml_result, "decision_confidence", None)
        if response_ml_confidence is None:
            response_ml_confidence = response_ml_result.ensemble_confidence
        response_ml_positive = getattr(
            response_ml_result, "decision_positive", None)
        if response_ml_positive is None:
            response_ml_positive = response_ml_result.ensemble_positive
        response_ml_verdicts = response_ml_result.verdicts

        combined = calculate_combined_confidence_active(
            injection_confidence=inj_conf,
            request_ml_confidence=ml_confidence,
            response_ml_confidence=response_ml_confidence,
        )
    elif ml_confidence is not None:
        # Passive mode: existing behavior unchanged
        combined = calculate_combined_confidence(inj_conf, ml_confidence)

    # Apply content analysis adjustments
    if content_analysis is not None:
        base = combined if combined is not None else inj_conf

        if content_analysis.is_blocked and not content_analysis.findings:
            # WAF/filter blocked, no sensitive data = false positive
            base = min(base, 15.0)
            inj_reason = f"BLOCKED: {content_analysis.block_reason}"
        elif content_analysis.findings:
            # Sensitive data found = boost confidence based on severity
            max_severity = max(
                (f.severity for f in content_analysis.findings),
                key=lambda s: {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}.get(s, 0),
            )

            if max_severity == 'CRITICAL':
                # Credentials, /etc/passwd, private keys = definite SSRF
                base = base + content_analysis.confidence_modifier
                base = max(base, 95.0)
            elif max_severity == 'HIGH':
                # Metadata, db leaks = very likely SSRF
                base = base + content_analysis.confidence_modifier
                base = max(base, 85.0)
            elif max_severity == 'MEDIUM':
                # External SSRF, internal services = mechanism confirmed
                # Don't inflate beyond 70% — it's confirmed but not critical
                base = min(base, 70.0)
                base = max(base, 60.0)

            base = min(100.0, base)

        combined = min(100.0, max(0.0, base))

    result = ConfidenceResult(
        injection_confidence=inj_conf,
        injection_level=inj_level,
        injection_reason=inj_reason,
        ml_confidence=ml_confidence,
        combined_confidence=combined,
        response_ml_confidence=response_ml_confidence,
        response_ml_verdicts=response_ml_verdicts,
        response_ml_positive=response_ml_positive,
    )

    # Attach content analysis data
    if content_analysis is not None:
        result.content_analysis = content_analysis
        result.content_blocked = content_analysis.is_blocked
        result.content_findings_count = len(content_analysis.findings)

    return result
