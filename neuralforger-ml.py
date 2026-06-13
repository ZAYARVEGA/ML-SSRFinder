#!/usr/bin/env python3
"""
Neural Forger - Machine Learning Integration Layer (Extension)

Wraps the detector module to provide a clean interface for ML-powered
analysis within the Neural Forger workflow. Handles caching, parameter
discovery, and result formatting for the inspection mode.

Public API:
    MLAnalyzer.analyze(request_data) -> MLResult
    MLAnalyzer.get_cached_result() -> Optional[MLResult]
    MLAnalyzer.discover_parameters(url, headers, body) -> list[ParameterInfo]
"""

import re
import time
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs

try:
    from colorama import Fore, Style
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class _Stub:
        def __getattr__(self, _):
            return ""
    Fore = Style = _Stub()

# Import the detector (hyphenated module name)
import importlib
import sys
import os

_detector_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "neuralforger-detector.py")
_spec = importlib.util.spec_from_file_location("neuralforger_detector", _detector_path)
_detector_mod = importlib.util.module_from_spec(_spec)
sys.modules["neuralforger_detector"] = _detector_mod
_spec.loader.exec_module(_detector_mod)

analyze_request = _detector_mod.analyze_request
get_recommended_payloads = _detector_mod.get_recommended_payloads
extract_features = _detector_mod.extract_features
calculate_score = _detector_mod.calculate_score


class ParameterInfo:
    """Information about a discovered parameter."""

    def __init__(
        self,
        name: str,
        location: str,
        value: str = "",
        confidence: float = 0.0,
        reason: str = "",
    ):
        self.name = name
        self.location = location  # 'query', 'body', 'header', 'path'
        self.value = value
        self.confidence = confidence
        self.reason = reason

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "value": self.value,
            "confidence": self.confidence,
            "reason": self.reason,
        }


class MLResult:
    """Container for ML analysis results."""

    def __init__(
        self,
        vulnerable: bool,
        confidence: int,
        risk_level: str,
        parameters: List[ParameterInfo],
        payloads: List[Dict[str, Any]],
        features: List[Dict[str, Any]],
        analysis_time_ms: float,
        endpoint: str = "",
    ):
        self.vulnerable = vulnerable
        self.confidence = confidence
        self.risk_level = risk_level
        self.parameters = parameters
        self.payloads = payloads
        self.features = features
        self.analysis_time_ms = analysis_time_ms
        self.endpoint = endpoint

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerable": self.vulnerable,
            "confidence": self.confidence,
            "risk_level": self.risk_level,
            "parameters": [p.to_dict() for p in self.parameters],
            "recommended_payloads": self.payloads,
            "features_detected": self.features,
            "analysis_time_ms": round(self.analysis_time_ms, 2),
            "endpoint": self.endpoint,
        }


# Known SSRF-indicative parameter names with base confidence scores
_PARAM_INDICATORS: Dict[str, Tuple[float, str]] = {
    "url":          (0.92, "Parameter name is 'url' (primary SSRF indicator)"),
    "uri":          (0.88, "Parameter name is 'uri' (direct URL reference)"),
    "href":         (0.85, "Parameter name is 'href' (hyperlink reference)"),
    "link":         (0.82, "Parameter name is 'link' (URL link reference)"),
    "src":          (0.80, "Parameter name is 'src' (source reference)"),
    "source":       (0.80, "Parameter name is 'source' (source reference)"),
    "redirect":     (0.78, "Redirection parameter (open redirect / SSRF vector)"),
    "redirect_url": (0.82, "Explicit redirect URL parameter"),
    "return_url":   (0.80, "Return URL parameter"),
    "callback":     (0.75, "Callback URL parameter"),
    "webhook":      (0.88, "Webhook URL parameter"),
    "webhookurl":   (0.90, "Explicit webhook URL parameter"),
    "dest":         (0.72, "Destination parameter"),
    "target":       (0.70, "Target URL parameter"),
    "fetch":        (0.85, "Fetch endpoint parameter"),
    "download":     (0.82, "Download URL parameter"),
    "load":         (0.78, "Load resource parameter"),
    "file":         (0.65, "File path parameter (potential SSRF via file://)"),
    "path":         (0.55, "Path parameter (moderate indicator)"),
    "next":         (0.60, "Next URL parameter (redirect chain)"),
    "image":        (0.62, "Image URL parameter"),
    "img":          (0.62, "Image URL parameter (short form)"),
    "proxy":        (0.85, "Proxy URL parameter"),
    "endpoint":     (0.75, "Endpoint URL parameter"),
    "api_url":      (0.88, "API URL parameter"),
}


class MLAnalyzer:
    """
    Machine learning analysis engine for SSRF detection.

    Provides parameter discovery, vulnerability scoring, and payload
    recommendations. Results are cached to avoid redundant computation.
    """

    def __init__(self) -> None:
        self._cache: Optional[MLResult] = None

    def analyze(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        target_parameter: Optional[str] = None,
        requires_auth: bool = False,
    ) -> MLResult:
        """
        Perform full ML analysis on an HTTP request.

        Args:
            url: Target endpoint URL.
            method: HTTP method.
            headers: Request headers.
            body: Request body.
            target_parameter: Specific parameter to analyze (optional).
            requires_auth: Whether authentication is required.

        Returns:
            MLResult containing vulnerability assessment.
        """
        start_time = time.perf_counter()
        headers = headers or {}

        # Discover parameters
        discovered_params = self.discover_parameters(url, headers, body)

        # If a target parameter is specified, focus analysis on it
        if target_parameter:
            analysis = analyze_request({
                "url": url,
                "method": method,
                "parameter_name": target_parameter,
                "requires_auth": requires_auth,
            })
        else:
            # Find the highest-risk parameter
            best_analysis = None
            best_confidence = -1

            for param_info in discovered_params:
                analysis = analyze_request({
                    "url": url,
                    "method": method,
                    "parameter_name": param_info.name,
                    "requires_auth": requires_auth,
                })
                if analysis["confidence"] > best_confidence:
                    best_confidence = analysis["confidence"]
                    best_analysis = analysis

            if best_analysis is None:
                analysis = analyze_request({
                    "url": url,
                    "method": method,
                    "parameter_name": "",
                    "requires_auth": requires_auth,
                })
            else:
                analysis = best_analysis

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Score each discovered parameter individually
        scored_params: List[ParameterInfo] = []
        for param_info in discovered_params:
            param_analysis = analyze_request({
                "url": url,
                "method": method,
                "parameter_name": param_info.name,
                "requires_auth": requires_auth,
            })
            param_info.confidence = float(param_analysis["confidence"])
            if not param_info.reason:
                param_lower = param_info.name.lower()
                for indicator, (_, desc) in _PARAM_INDICATORS.items():
                    if indicator in param_lower:
                        param_info.reason = desc
                        break
                if not param_info.reason:
                    param_info.reason = "Parameter detected in request"
            scored_params.append(param_info)

        scored_params.sort(key=lambda p: p.confidence, reverse=True)

        result = MLResult(
            vulnerable=analysis["vulnerable"],
            confidence=analysis["confidence"],
            risk_level=analysis["risk_level"],
            parameters=scored_params,
            payloads=analysis.get("recommended_payloads", []),
            features=analysis.get("feature_details", []),
            analysis_time_ms=elapsed_ms,
            endpoint=url,
        )

        self._cache = result
        return result

    def get_cached_result(self) -> Optional[MLResult]:
        """Retrieve the last cached analysis result."""
        return self._cache

    def discover_parameters(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
    ) -> List[ParameterInfo]:
        """
        Discover potentially injectable parameters in the request.

        Examines URL query string, request body (form-encoded and JSON),
        and select headers for parameters that may accept URL values.

        Args:
            url: Target URL.
            headers: Request headers.
            body: Request body string.

        Returns:
            List of ParameterInfo objects for discovered parameters.
        """
        headers = headers or {}
        params: List[ParameterInfo] = []
        seen_names: set = set()

        # 1. Query string parameters
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for name, values in query_params.items():
                if name not in seen_names:
                    value = values[0] if values else ""
                    conf, reason = self._score_parameter_name(name, value)
                    params.append(ParameterInfo(
                        name=name, location="query", value=value,
                        confidence=conf, reason=reason,
                    ))
                    seen_names.add(name)
        except Exception:
            pass

        # 2. Body parameters (form-encoded)
        if body and "=" in body and not body.strip().startswith("{"):
            try:
                body_params = parse_qs(body, keep_blank_values=True)
                for name, values in body_params.items():
                    if name not in seen_names:
                        value = values[0] if values else ""
                        conf, reason = self._score_parameter_name(name, value)
                        params.append(ParameterInfo(
                            name=name, location="body", value=value,
                            confidence=conf, reason=reason,
                        ))
                        seen_names.add(name)
            except Exception:
                pass

        # 3. Body parameters (JSON)
        if body and body.strip().startswith("{"):
            try:
                import json
                json_body = json.loads(body)
                if isinstance(json_body, dict):
                    for name, value in json_body.items():
                        if name not in seen_names:
                            str_value = str(value) if value is not None else ""
                            conf, reason = self._score_parameter_name(name, str_value)
                            params.append(ParameterInfo(
                                name=name, location="body", value=str_value,
                                confidence=conf, reason=reason,
                            ))
                            seen_names.add(name)
            except (ImportError, ValueError):
                pass

        return params

    @staticmethod
    def _score_parameter_name(name: str, value: str = "") -> Tuple[float, str]:
        """
        Score a parameter name for SSRF likelihood.

        Args:
            name: Parameter name.
            value: Parameter value (used for heuristic boost).

        Returns:
            Tuple of (confidence_percentage, reason_string).
        """
        name_lower = name.lower()
        best_conf = 0.0
        best_reason = ""

        for indicator, (conf, reason) in _PARAM_INDICATORS.items():
            if indicator == name_lower:
                if conf > best_conf:
                    best_conf = conf
                    best_reason = reason
            elif indicator in name_lower:
                adjusted = conf * 0.85
                if adjusted > best_conf:
                    best_conf = adjusted
                    best_reason = reason

        # Boost if value looks like a URL
        if value and re.match(r"https?://", value, re.IGNORECASE):
            best_conf = min(0.99, best_conf + 0.10)
            if not best_reason:
                best_reason = "Parameter value contains a URL"

        confidence_pct = best_conf * 100.0

        if not best_reason:
            best_reason = "No known SSRF indicator detected"
            confidence_pct = max(confidence_pct, 5.0)

        return confidence_pct, best_reason
