#!/usr/bin/env python3
"""
ML-SSRFinder v1.0.0 - ML-Powered SSRF Detection Framework

Extension for SSRFinder. Adds ML pre-analysis, combined confidence
scoring, and professional output formatting on top of SSRFinder's
core injection engine.

Usage:
    python3 mlssrfinder-main.py -r request.txt -i
    python3 mlssrfinder-main.py -r request.txt -p url
    python3 mlssrfinder-main.py -u "http://target/api?url=SSRF" -p url
"""

import signal
import sys
import os
import importlib.util
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

# ============================================================================
# Module loader for hyphenated filenames
# ============================================================================

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Ensure base directory is in path so SSRFinder modules can be imported
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)


def _load_module(name: str, filename: str):
    """Load a module from a hyphenated filename."""
    if name in sys.modules:
        return sys.modules[name]
    path = os.path.join(_BASE_DIR, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# ============================================================================
# Import SSRFinder base modules (the core engine)
# ============================================================================

from request_parser import parse_raw_request
from request_sender import create_session, send_request
from injection_handler import find_injection_point, replace_injection_point
from payload_generator import generate_payloads as ssrf_generate_payloads
from response_formatter import format_response_preview
from network_parser import parse_ip_range, parse_ports
from url_encoding import url_encode_payload, add_path_to_payload

# ============================================================================
# Load ML-SSRFinder extension modules (hyphenated names)
# ============================================================================

config = _load_module("mlssrfinder_config", "mlssrfinder-config.py")
banner_mod = _load_module("mlssrfinder_banner", "mlssrfinder-banner.py")
cli_mod = _load_module("mlssrfinder_cli", "mlssrfinder-cli.py")
ml_mod = _load_module("mlssrfinder_ml", "mlssrfinder-ml.py")
confidence_mod = _load_module("mlssrfinder_confidence", "mlssrfinder-confidence.py")
output_mod = _load_module("mlssrfinder_output", "mlssrfinder-output.py")
response_ml_mod = _load_module("mlssrfinder_response_ml", "mlssrfinder-response-ml.py")

try:
    from colorama import Fore, Style
except ImportError:
    class _Stub:
        def __getattr__(self, _):
            return ""
    Fore = Style = _Stub()


# ============================================================================
# Signal handler
# ============================================================================

def _signal_handler(sig, frame):
    """Handle CTRL+C gracefully."""
    print(f"\n\n{config.INDICATOR_WARNING} Scan interrupted by user (SIGINT)")
    print(f"{config.INDICATOR_INFO} Partial results may be available.")
    sys.exit(config.EXIT_ERROR)


signal.signal(signal.SIGINT, _signal_handler)


# ============================================================================
# ML-enhanced payload generation
# ============================================================================

def generate_ml_payloads(
    ml_recommendations: List[Dict[str, Any]],
    max_payloads: int = 5,
) -> List[str]:
    """
    Extract payloads from ML recommendations.

    Args:
        ml_recommendations: Payload recommendation list from the ML detector.
        max_payloads: Maximum number of payloads to return.

    Returns:
        List of payload strings.
    """
    payloads: List[str] = []
    for rec in ml_recommendations:
        if len(payloads) >= max_payloads:
            break
        primary = rec.get("payload", "")
        if primary and primary not in payloads:
            payloads.append(primary)
        for alt in rec.get("alternatives", []):
            if len(payloads) >= max_payloads:
                break
            if alt and alt not in payloads:
                payloads.append(alt)
    return payloads


def generate_nf_payloads(
    single_url: Optional[str] = None,
    single_ip: Optional[str] = None,
    wordlist: Optional[str] = None,
    ip_range: Optional[str] = None,
    ports: Optional[str] = None,
    path: Optional[str] = None,
    encode: str = "none",
    ml_recommendations: Optional[List[Dict[str, Any]]] = None,
    payload_strategy: str = "ml-recommended",
) -> List[str]:
    """
    Generate payloads using SSRFinder's base generator enhanced with ML strategy.

    For explicit targets (single_url, single_ip, wordlist, ip_range), delegates
    directly to SSRFinder's generate_payloads. For strategy-based selection,
    prepends ML-recommended payloads before SSRFinder's defaults.

    Args:
        single_url: Specific URL to test.
        single_ip: Specific IP to scan across ports.
        wordlist: Path to custom wordlist.
        ip_range: IP range specification.
        ports: Port specification.
        path: Path to append to payloads.
        encode: URL encoding type.
        ml_recommendations: ML-recommended payloads.
        payload_strategy: Strategy for payload selection.

    Returns:
        List of ready-to-use payload strings.
    """
    # If explicit target is specified, use SSRFinder's base generator directly
    if single_url or single_ip or wordlist or ip_range:
        return ssrf_generate_payloads(
            single_url=single_url,
            single_ip=single_ip,
            wordlist=wordlist,
            ip_range=ip_range,
            ports=ports,
            path=path,
            encode=encode,
        )

    # Strategy-based selection with ML integration
    from config import DEFAULT_PAYLOADS, DEFAULT_PORTS

    ml_payloads = []
    if ml_recommendations:
        ml_payloads = generate_ml_payloads(ml_recommendations)

    if payload_strategy == "ml-only":
        base_payloads = ml_payloads if ml_payloads else DEFAULT_PAYLOADS[:5]

    elif payload_strategy == "ml-recommended":
        # ML payloads first, then defaults (deduplicated)
        seen = set()
        combined: List[str] = []
        for p in ml_payloads + DEFAULT_PAYLOADS:
            if p not in seen:
                combined.append(p)
                seen.add(p)
        base_payloads = combined

    elif payload_strategy == "all":
        seen = set()
        combined = []
        for p in ml_payloads + DEFAULT_PAYLOADS:
            if p not in seen:
                combined.append(p)
                seen.add(p)
        base_payloads = combined

    else:
        base_payloads = DEFAULT_PAYLOADS.copy()

    # Apply custom ports to default payloads if specified
    if ports:
        port_list = parse_ports(ports)
        enhanced: List[str] = []
        for payload in base_payloads:
            if "://" in payload:
                scheme, rest = payload.split("://", 1)
                if "/" in rest:
                    host, path_part = rest.split("/", 1)
                    path_part = "/" + path_part
                else:
                    host = rest
                    path_part = ""
                if ":" in host and not host.startswith("["):
                    host = host.split(":")[0]
                for port in port_list:
                    enhanced.append(f"{scheme}://{host}:{port}{path_part}")
            else:
                enhanced.append(payload)
        if enhanced:
            base_payloads = enhanced

    # Apply path suffix
    if path:
        base_payloads = [add_path_to_payload(p, path) for p in base_payloads]

    # Apply URL encoding
    if encode != "none":
        base_payloads = [url_encode_payload(p, encode) for p in base_payloads]

    return base_payloads


# ============================================================================
# Request parsing helpers (extend SSRFinder's parser)
# ============================================================================

def detect_auth_header(headers: Dict[str, str]) -> bool:
    """
    Determine whether authentication headers are present.

    Args:
        headers: Request headers dictionary.

    Returns:
        True if authentication-related headers are detected.
    """
    auth_indicators = {
        "authorization",
        "x-api-key",
        "x-auth-token",
        "cookie",
        "x-csrf-token",
        "x-session-id",
    }
    header_keys_lower = {k.lower() for k in headers.keys()}
    return bool(auth_indicators & header_keys_lower)


def build_full_request_text(
    url: str,
    headers: Dict[str, str],
    body: str = "",
) -> str:
    """
    Reconstruct full request text from components for marker detection.

    Args:
        url: Request URL.
        headers: Headers dictionary.
        body: Request body.

    Returns:
        Reconstructed request as a single string.
    """
    parts = [url]
    for key, value in headers.items():
        parts.append(f"{key}: {value}")
    if body:
        parts.append("")
        parts.append(body)
    return "\n".join(parts)


# ============================================================================
# Response wrapper (extends SSRFinder's send_request with timing)
# ============================================================================

import time


def send_timed_request(session, method, url, headers, body, timeout):
    """
    Send request using SSRFinder's sender and add timing information.

    Returns a dict with: status_code, response_size, response_time_ms,
    error, headers, content, success.
    """
    start_time = time.perf_counter()
    status_code, response_size, error, resp_headers, resp_content = send_request(
        session, method, url, headers, body, timeout
    )
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    return {
        "status_code": status_code,
        "response_size": response_size,
        "response_time_ms": elapsed_ms,
        "error": error,
        "headers": resp_headers,
        "content": resp_content,
        "success": error is None and status_code is not None,
    }


# ============================================================================
# Inspection mode workflow
# ============================================================================

def run_inspect_mode(
    args,
    out: output_mod.OutputFormatter,
    method: str,
    url: str,
    headers: Dict[str, str],
    body: str,
    host: str,
) -> None:
    """
    Execute ML inspection mode without injection testing.
    """
    out.info(f"{config.TOOL_NAME} v{config.VERSION} - {config.TOOL_DESCRIPTION}")
    out.info(f"Request file: {args.request}")
    out.info("Initiating ML analysis...")
    out.blank()

    has_auth = detect_auth_header(headers)

    analyzer = ml_mod.MLAnalyzer()
    ml_result = analyzer.analyze(
        url=url,
        method=method,
        headers=headers,
        body=body,
        requires_auth=has_auth,
    )

    out.print_ml_analysis(ml_result)

    if ml_result.vulnerable and ml_result.parameters:
        best_param = ml_result.parameters[0].name
        request_file = args.request or "<request_file>"
        out.print_inspect_followup(request_file, best_param)
    elif ml_result.vulnerable:
        out.success("ML analysis indicates vulnerability. Specify a parameter with -p for injection testing.")
    else:
        out.info("ML analysis does not indicate high SSRF probability.")
        out.info("Consider testing with -p if you have additional context.")

    out.blank()


# ============================================================================
# Injection mode workflow
# ============================================================================

def run_injection_mode(
    args,
    out: output_mod.OutputFormatter,
    method: str,
    url: str,
    headers: Dict[str, str],
    body: str,
    host: str,
) -> int:
    """
    Execute injection testing mode with ML pre-analysis.

    Uses SSRFinder's core injection engine (find_injection_point,
    replace_injection_point, send_request) combined with ML-SSRFinder's
    ML analysis and combined confidence scoring.
    """
    out.info(f"{config.TOOL_NAME} v{config.VERSION} - {config.TOOL_DESCRIPTION}")

    has_auth = detect_auth_header(headers)

    # ML pre-analysis
    analyzer = ml_mod.MLAnalyzer()
    ml_result = analyzer.analyze(
        url=url,
        method=method,
        headers=headers,
        body=body,
        target_parameter=args.param,
        requires_auth=has_auth,
    )

    out.info(f"ML Pre-Analysis: {ml_result.confidence}% vulnerability probability")
    out.info(f"Target Parameter: {args.param}")

    # Check confidence threshold
    if ml_result.confidence < args.confidence_threshold and args.payload_strategy == "ml-only":
        out.warning(
            f"ML confidence ({ml_result.confidence}%) below threshold "
            f"({args.confidence_threshold}%)"
        )
        out.info("Use --payload-strategy all or lower --confidence-threshold to proceed.")
        return config.EXIT_SUCCESS

    out.info(f"Strategy: {args.payload_strategy}")

    # Initialize Response ML Analyzer if --response-ml is active
    response_ml_analyzer = None
    if hasattr(args, 'response_ml') and args.response_ml:
        response_ml_analyzer = response_ml_mod.ResponseMLAnalyzer(
            models_dir=_BASE_DIR,
        )
        if not response_ml_analyzer.is_available():
            out.warning("No response ML models found. --response-ml disabled.")
            response_ml_analyzer = None
        else:
            out.info("Response ML analysis enabled (active mode).")

    # Build full request text for marker detection (using SSRFinder's logic)
    full_request = build_full_request_text(url, headers, body)
    found, marker = find_injection_point(full_request)

    if not found:
        out.error(
            "Injection marker not found in request.\n"
            "    Expected one of: SSRF, ***, INJECT, FUZZ\n"
            "    Place the marker at the desired injection point."
        )
        return config.EXIT_ERROR

    out.verbose(f"Injection marker: '{marker}'")

    # Establish baseline using SSRFinder's request sender
    out.info("Establishing baseline response...")

    # Create session (SSRFinder's create_session + proxy if specified)
    session = create_session()
    if hasattr(args, 'proxy') and args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}

    baseline_url = replace_injection_point(url, marker, "")
    baseline_headers = {
        k: replace_injection_point(v, marker, "")
        for k, v in headers.items()
    }
    baseline_body = replace_injection_point(body, marker, "") if body else ""

    baseline = send_timed_request(
        session, method, baseline_url, baseline_headers, baseline_body, args.timeout,
    )

    baseline_size = baseline["response_size"] or 0
    if baseline["success"]:
        out.info(f"Baseline: Status {baseline['status_code']}, Size {baseline_size} bytes")
    else:
        out.warning(f"Baseline request failed: {baseline['error']}")
        out.info("Continuing with zero baseline...")

    # Generate payloads using ML-enhanced generator
    ml_recommendations = ml_result.payloads if ml_result.vulnerable else None
    payloads = generate_nf_payloads(
        single_url=args.single_url,
        single_ip=args.ip,
        wordlist=args.wordlist,
        ip_range=args.ip_range,
        ports=args.ports,
        path=args.path,
        encode=args.encode,
        ml_recommendations=ml_recommendations,
        payload_strategy=args.payload_strategy,
    )

    total_payloads = len(payloads)
    out.info(f"Testing {total_payloads} payloads...")
    out.blank()

    if out.verbosity >= 1:
        out.separator("-")
        out.plain("PAYLOAD INJECTION RESULTS")
        out.separator("-")
        out.blank()

    # Execute injection tests using SSRFinder's core
    results: List[Dict[str, Any]] = []
    best_injection_confidence = 0.0

    for idx, payload in enumerate(payloads, 1):
        # Inject payload using SSRFinder's injection handler
        test_url = replace_injection_point(url, marker, payload)
        test_headers = {
            k: replace_injection_point(v, marker, payload)
            for k, v in headers.items()
        }
        test_body = replace_injection_point(body, marker, payload) if body else ""

        # Send request with timing
        resp = send_timed_request(
            session, method, test_url, test_headers, test_body, args.timeout,
        )

        # Calculate confidence using ML-SSRFinder's enhanced scoring
        if resp["success"]:
            if baseline_size > 0:
                size_diff = abs((resp["response_size"] - baseline_size) / baseline_size * 100)
            else:
                size_diff = 100.0 if resp["response_size"] > 0 else 0.0

            # Response ML analysis (active mode)
            response_ml_result = None
            content_analysis = None

            if response_ml_analyzer is not None:
                # Build a lightweight response_data object for the analyzer
                class _ResponseDataProxy:
                    pass
                rd = _ResponseDataProxy()
                rd.status_code = resp["status_code"]
                rd.response_size_bytes = resp["response_size"]
                rd.response_time_ms = resp["response_time_ms"]
                rd.headers = resp["headers"] or {}
                rd.content = resp["content"] or b''
                rd.error = None

                response_ml_result = response_ml_analyzer.analyze(rd)

                # Content analysis: detect WAF blocks + sensitive data
                content_analysis = response_ml_mod.analyze_response_content(
                    body=resp["content"] or b'',
                    headers=resp["headers"],
                    payload=payload,
                )

            conf_result = confidence_mod.build_confidence_result(
                status_code=resp["status_code"],
                size_diff_percent=size_diff,
                response_time_ms=resp["response_time_ms"],
                ml_confidence=float(ml_result.confidence),
                response_ml_result=response_ml_result,
                content_analysis=content_analysis,
            )

            # Detect critical findings (enhanced with content analysis)
            is_critical = False
            critical_reason = ""

            if content_analysis and content_analysis.findings:
                # Content analysis found sensitive data
                best = max(
                    content_analysis.findings,
                    key=lambda f: {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}.get(f.severity, 0),
                )
                if best.severity == 'CRITICAL':
                    is_critical = True
                    critical_reason = best.description
                elif best.severity == 'HIGH':
                    is_critical = True
                    critical_reason = best.description

            if not is_critical:
                if "169.254.169.254" in payload and resp["status_code"] == 200 and size_diff > 10:
                    is_critical = True
                    critical_reason = "Cloud metadata accessible"
                elif "metadata.google.internal" in payload and resp["status_code"] == 200:
                    is_critical = True
                    critical_reason = "GCP metadata accessible"

            inj_conf = conf_result.injection_confidence
            combined = conf_result.combined_confidence or inj_conf

            if inj_conf > best_injection_confidence:
                best_injection_confidence = inj_conf

            result = {
                "payload": payload,
                "status_code": resp["status_code"],
                "response_size": resp["response_size"],
                "response_time_ms": resp["response_time_ms"],
                "size_diff_percent": size_diff,
                "injection_confidence": inj_conf,
                "combined_confidence": combined,
                "confidence_level": conf_result.injection_level,
                "severity": conf_result.severity,
                "error": None,
                "is_critical": is_critical,
                "critical_reason": critical_reason,
                "headers": resp["headers"],
                "content": resp["content"],
                "response_ml_confidence": conf_result.response_ml_confidence,
                "response_ml_positive": conf_result.response_ml_positive,
            }
            results.append(result)

            out.print_injection_result(
                index=idx,
                total=total_payloads,
                payload=payload,
                status_code=resp["status_code"],
                response_size=resp["response_size"],
                response_time_ms=resp["response_time_ms"],
                confidence=combined,
                confidence_level=conf_result.injection_level,
                is_critical=is_critical,
                critical_reason=critical_reason,
                response_ml_result=response_ml_result,
                content_analysis=content_analysis,
            )

            # Show response content if requested
            if args.show_response and inj_conf >= 70.0 and resp["content"]:
                out.verbose("Response preview:")
                preview = format_response_preview(resp["content"], max_length=300)
                for line in preview.split("\n")[:8]:
                    out.verbose(f"  {line}")
                out.blank()

        else:
            result = {
                "payload": payload,
                "status_code": None,
                "response_size": None,
                "response_time_ms": resp["response_time_ms"],
                "size_diff_percent": None,
                "injection_confidence": 0.0,
                "combined_confidence": 0.0,
                "confidence_level": "NONE",
                "severity": "INFO",
                "error": resp["error"],
                "is_critical": False,
                "critical_reason": "",
                "headers": None,
                "content": None,
            }
            results.append(result)

            out.print_injection_result(
                index=idx,
                total=total_payloads,
                payload=payload,
                status_code=None,
                response_size=None,
                response_time_ms=resp["response_time_ms"],
                confidence=0.0,
                confidence_level="NONE",
                error=resp["error"],
            )

        # Progress for quiet mode
        if out.verbosity == 0:
            out.print_progress(idx, total_payloads)

    # Calculate summary statistics
    vulnerable_results = [r for r in results if r["injection_confidence"] >= 70.0]
    vulnerable_count = len(vulnerable_results)

    combined_confidence = None
    if response_ml_analyzer is not None and any(r.get("response_ml_confidence") is not None for r in results):
        # Active mode: use the best combined confidence from per-payload results
        # (already computed with active weights)
        valid_combined = [r["combined_confidence"] for r in results if r.get("combined_confidence")]
        if valid_combined:
            combined_confidence = max(valid_combined)
    elif ml_result.confidence is not None:
        combined_confidence = confidence_mod.calculate_combined_confidence(
            best_injection_confidence,
            float(ml_result.confidence),
        )

    severity = "INFO"
    if vulnerable_count > 0:
        max_severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        severity = max(
            (r["severity"] for r in vulnerable_results),
            key=lambda s: max_severity_order.get(s, 0),
        )

    out.print_assessment_summary(
        vulnerable_count=vulnerable_count,
        total_tested=total_payloads,
        ml_confidence=float(ml_result.confidence),
        best_injection_confidence=best_injection_confidence,
        combined_confidence=combined_confidence,
        severity=severity,
        results=results,
    )

    return config.EXIT_VULNERABLE if vulnerable_count > 0 else config.EXIT_SUCCESS


# ============================================================================
# Main
# ============================================================================

def main() -> int:
    """
    Main entry point for ML-SSRFinder.

    Returns:
        Exit code.
    """
    parser = cli_mod.create_argument_parser()
    args = parser.parse_args()

    # Handle --manual
    if args.manual:
        cli_mod.print_manual()
        return config.EXIT_SUCCESS

    # Validate arguments
    cli_mod.validate_arguments(args)

    # Determine verbosity
    if args.quiet:
        verbosity = 0
    elif args.verbose:
        verbosity = 2
    else:
        verbosity = 1

    # Print ML-SSRFinder banner
    banner_mod.print_banner(version=config.VERSION, verbosity=verbosity)

    # Create output formatter
    out = output_mod.OutputFormatter(
        verbosity=verbosity,
        output_format=args.format,
        output_file=args.output,
    )
    out.open_output_file()

    try:
        # Parse request using SSRFinder's request_parser
        if args.request:
            try:
                method, url, headers, body, host = parse_raw_request(args.request)
            except Exception as exc:
                out.error(str(exc))
                return config.EXIT_ERROR

            if verbosity >= 2:
                out.verbose(f"Method: {method}")
                out.verbose(f"URL: {url}")
                out.verbose(f"Host: {host}")
                if body:
                    out.verbose(f"Body: {body[:100]}{'...' if len(body) > 100 else ''}")
                out.blank()

        elif args.url:
            method = "GET"
            url = args.url
            headers = {}
            body = ""
            host = ""
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host = parsed.hostname or ""
            except Exception:
                pass
        else:
            out.error("No request source specified. Use -r or -u.")
            return config.EXIT_ERROR

        # Route to appropriate workflow
        if args.inspect:
            run_inspect_mode(args, out, method, url, headers, body, host)
            return config.EXIT_SUCCESS
        elif args.param:
            exit_code = run_injection_mode(args, out, method, url, headers, body, host)
            return exit_code
        else:
            out.error("No operation mode specified. Use -i or -p.")
            return config.EXIT_ERROR

    except Exception as exc:
        out.error(f"Unexpected error: {exc}")
        if verbosity >= 2:
            import traceback
            traceback.print_exc()
        return config.EXIT_ERROR

    finally:
        out.close_output_file()


if __name__ == "__main__":
    sys.exit(main())
