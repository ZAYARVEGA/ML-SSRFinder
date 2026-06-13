#!/usr/bin/env python3
"""
Neural Forger - Integration Test Suite

Validates core workflows: ML inspection, parameter discovery,
payload generation, confidence scoring, and CLI argument parsing.

Tests both SSRFinder base modules and Neural Forger extension modules
to ensure the integrated system works correctly.

Run: python3 neuralforger-test.py
"""

import sys
import os
import importlib.util

# ============================================================================
# Module loader
# ============================================================================

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Ensure base dir is in path for SSRFinder imports
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)


def _load(name, filename):
    if name in sys.modules:
        return sys.modules[name]
    path = os.path.join(_BASE_DIR, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# Neural Forger extension modules (hyphenated names)
config = _load("neuralforger_config", "neuralforger-config.py")
detector = _load("neuralforger_detector", "neuralforger-detector.py")
ml = _load("neuralforger_ml", "neuralforger-ml.py")
confidence = _load("neuralforger_confidence", "neuralforger-confidence.py")
cli = _load("neuralforger_cli", "neuralforger-cli.py")
banner_nf = _load("neuralforger_banner", "neuralforger-banner.py")
output = _load("neuralforger_output", "neuralforger-output.py")

# SSRFinder base modules (used directly)
import request_parser
import injection_handler
import network_parser
import url_encoding
import payload_generator

# ============================================================================
# Test infrastructure
# ============================================================================

passed = 0
failed = 0
errors = []


def test(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        msg = f"  [FAIL] {name}"
        if detail:
            msg += f" -- {detail}"
        print(msg)
        errors.append(name)


# ============================================================================
# Test suites
# ============================================================================

def test_detector():
    print("\n[*] Testing ML Detector...")

    # Vulnerable endpoint
    result = detector.detect_ssrf("http://shop.com/fetch?url=test", "url")
    test("detect_ssrf: url param -> vulnerable", result is True)

    # Safe endpoint
    result = detector.detect_ssrf("https://api.github.com/users", "page", requires_auth=True)
    test("detect_ssrf: safe endpoint -> not vulnerable", result is False)

    # Full analysis
    analysis = detector.analyze_request({
        "url": "http://shop.com/api/fetch?url=test",
        "method": "GET",
        "parameter_name": "url",
        "requires_auth": False,
    })
    test("analyze_request: returns dict", isinstance(analysis, dict))
    test("analyze_request: vulnerable=True", analysis["vulnerable"] is True)
    test("analyze_request: confidence >= 50", analysis["confidence"] >= 50)
    test("analyze_request: has payloads", len(analysis["recommended_payloads"]) > 0)
    test("analyze_request: risk_level is string", isinstance(analysis["risk_level"], str))

    # Payload recommendations
    payloads = detector.get_recommended_payloads("http://site.com/fetch?url=x", "url")
    test("get_recommended_payloads: returns list", isinstance(payloads, list))
    test("get_recommended_payloads: non-empty", len(payloads) > 0)
    test("get_recommended_payloads: has success_rate", "success_rate" in payloads[0])


def test_ml_analyzer():
    print("\n[*] Testing ML Analyzer...")

    analyzer = ml.MLAnalyzer()

    # Analyze vulnerable request
    result = analyzer.analyze(
        url="http://target.com/api/fetch?url=test&format=json",
        method="GET",
        headers={"Host": "target.com"},
        body="",
    )
    test("MLAnalyzer.analyze: returns MLResult", hasattr(result, "vulnerable"))
    test("MLAnalyzer.analyze: vulnerable=True for url param", result.vulnerable is True)
    test("MLAnalyzer.analyze: has parameters", len(result.parameters) > 0)
    test("MLAnalyzer.analyze: has payloads", len(result.payloads) > 0)
    test("MLAnalyzer.analyze: timing > 0", result.analysis_time_ms > 0)

    # Check caching
    cached = analyzer.get_cached_result()
    test("MLAnalyzer.get_cached_result: returns cached", cached is not None)
    test("MLAnalyzer.get_cached_result: same result", cached.confidence == result.confidence)

    # Parameter discovery
    params = analyzer.discover_parameters(
        url="http://target.com/api/fetch?url=test&redirect=http://other.com&page=1",
        headers={},
        body="",
    )
    test("discover_parameters: finds multiple params", len(params) >= 2)
    param_names = [p.name for p in params]
    test("discover_parameters: finds 'url'", "url" in param_names)
    test("discover_parameters: finds 'redirect'", "redirect" in param_names)

    # Analyze safe endpoint
    safe_result = analyzer.analyze(
        url="https://api.github.com/users?page=1",
        method="GET",
        headers={"Authorization": "Bearer token"},
        body="",
        requires_auth=True,
    )
    test("MLAnalyzer: safe endpoint has lower confidence",
         safe_result.confidence < result.confidence,
         f"safe={safe_result.confidence} vs vuln={result.confidence}")


def test_request_parser():
    """Test SSRFinder's request parser (base module)."""
    print("\n[*] Testing Request Parser (SSRFinder base)...")

    # Write temp request file
    tmp = os.path.join(_BASE_DIR, "_test_request.txt")
    with open(tmp, "w") as f:
        f.write("GET /api/fetch?url=SSRF HTTP/1.1\nHost: example.com\nAuthorization: Bearer tok\n\n")

    try:
        method, url, headers, body, host = request_parser.parse_raw_request(tmp)
        test("parse_raw_request: method=GET", method == "GET")
        test("parse_raw_request: host=example.com", host == "example.com")
        test("parse_raw_request: url contains host", "example.com" in url)
        test("parse_raw_request: has auth header", "Authorization" in headers)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def test_injection():
    """Test SSRFinder's injection handler (base module)."""
    print("\n[*] Testing Injection Handler (SSRFinder base)...")

    text = "GET /api?url=SSRF HTTP/1.1"
    found, marker = injection_handler.find_injection_point(text)
    test("find_injection_point: finds SSRF", found is True)
    test("find_injection_point: marker='SSRF'", marker == "SSRF")

    result = injection_handler.replace_injection_point(text, "SSRF", "http://localhost")
    test("replace_injection_point: replaces marker", "http://localhost" in result)
    test("replace_injection_point: no marker left", "SSRF" not in result)

    # Test *** marker
    text2 = "GET /api?url=*** HTTP/1.1"
    found2, marker2 = injection_handler.find_injection_point(text2)
    test("find_injection_point: finds ***", found2 is True and marker2 == "***")


def test_confidence():
    print("\n[*] Testing Confidence Calculator (NF extension)...")

    # High confidence: 200 with size diff
    conf, level, reason = confidence.calculate_injection_confidence(200, 50.0)
    test("confidence: 200 + diff -> HIGH", level == "HIGH")
    test("confidence: 200 + diff -> >= 90", conf >= 90.0)

    # Low: connection failed
    conf, level, reason = confidence.calculate_injection_confidence(None, 0.0)
    test("confidence: None status -> NONE", level == "NONE")

    # Combined
    combined = confidence.calculate_combined_confidence(90.0, 80.0)
    expected = 90.0 * 0.70 + 80.0 * 0.30
    test("combined_confidence: correct calculation", abs(combined - expected) < 0.1,
         f"got {combined}, expected {expected}")

    # ConfidenceResult
    result = confidence.build_confidence_result(200, 50.0, 250.0, 85.0)
    test("build_confidence_result: has severity", hasattr(result, "severity"))
    test("build_confidence_result: is_vulnerable", result.is_vulnerable is True)


def test_network():
    """Test SSRFinder's network parser (base module)."""
    print("\n[*] Testing Network Utilities (SSRFinder base)...")

    ips = network_parser.parse_ip_range("192.168.1.1-5")
    test("parse_ip_range: correct count", len(ips) == 5)
    test("parse_ip_range: first IP", ips[0] == "192.168.1.1")
    test("parse_ip_range: last IP", ips[-1] == "192.168.1.5")

    ports = network_parser.parse_ports("80,443,8000-8002")
    test("parse_ports: correct count", len(ports) == 5)
    test("parse_ports: sorted", ports == sorted(ports))

    encoded = url_encoding.url_encode_payload("http://localhost", "single")
    test("url_encode: single encoding", "%" in encoded)

    with_path = url_encoding.add_path_to_payload("http://localhost", "/admin")
    test("add_path: appends correctly", with_path == "http://localhost/admin")


def test_payload_generator():
    """Test SSRFinder's payload generator (base module)."""
    print("\n[*] Testing Payload Generator (SSRFinder base)...")

    # Default payloads
    payloads = payload_generator.generate_payloads()
    test("generate_payloads: default non-empty", len(payloads) > 0)
    test("generate_payloads: contains localhost",
         any("localhost" in p for p in payloads))


def test_nf_payload_integration():
    """Test NeuralForger's ML-enhanced payload generation."""
    print("\n[*] Testing NF Payload Integration...")

    nf_main = _load("neuralforger_main", "neuralforger-main.py")

    ml_recs = [
        {"category": "localhost", "priority": "HIGH", "success_rate": 37,
         "payload": "http://localhost/admin", "alternatives": ["http://127.0.0.1/admin"]},
    ]

    # ML-only strategy
    ml_payloads = nf_main.generate_nf_payloads(
        ml_recommendations=ml_recs, payload_strategy="ml-only",
    )
    test("generate_nf_payloads: ml-only uses ML recs", "http://localhost/admin" in ml_payloads)

    # ML-recommended strategy (ML first, then defaults)
    combined = nf_main.generate_nf_payloads(
        ml_recommendations=ml_recs, payload_strategy="ml-recommended",
    )
    test("generate_nf_payloads: ml-recommended starts with ML",
         combined[0] == "http://localhost/admin")
    test("generate_nf_payloads: ml-recommended includes defaults",
         len(combined) > len(ml_recs[0]["alternatives"]) + 1)

    # Verify it delegates to SSRFinder for explicit targets
    single_payloads = nf_main.generate_nf_payloads(
        single_url="http://test.com/specific",
    )
    test("generate_nf_payloads: single_url delegates to SSRFinder",
         single_payloads == ["http://test.com/specific"])


def test_cli():
    print("\n[*] Testing CLI Parser (NF extension)...")

    parser = cli.create_argument_parser()
    test("create_argument_parser: returns parser", parser is not None)

    # Test parsing valid args
    args = parser.parse_args(["-r", "test.txt", "-i"])
    test("CLI: -r test.txt -i", args.request == "test.txt" and args.inspect is True)

    args = parser.parse_args(["-r", "test.txt", "-p", "url", "-v"])
    test("CLI: -r test.txt -p url -v",
         args.request == "test.txt" and args.param == "url" and args.verbose is True)

    args = parser.parse_args(["-r", "test.txt", "-p", "url", "--format", "json", "-o", "out.json"])
    test("CLI: format and output", args.format == "json" and args.output == "out.json")

    # NF-specific arguments
    args = parser.parse_args(["-r", "test.txt", "-p", "url", "--payload-strategy", "ml-only"])
    test("CLI: payload-strategy", args.payload_strategy == "ml-only")

    args = parser.parse_args(["-r", "test.txt", "-p", "url", "--confidence-threshold", "50"])
    test("CLI: confidence-threshold", args.confidence_threshold == 50)

    args = parser.parse_args(["-r", "test.txt", "-p", "url", "--proxy", "http://127.0.0.1:8080"])
    test("CLI: proxy", args.proxy == "http://127.0.0.1:8080")


def test_output():
    print("\n[*] Testing Output Formatter (NF extension)...")

    formatter = output.OutputFormatter(verbosity=1, output_format="text")
    test("OutputFormatter: creates instance", formatter is not None)
    test("OutputFormatter: verbosity=1", formatter.verbosity == 1)


def test_banner():
    print("\n[*] Testing Banner (NF extension)...")

    text = banner_nf.get_banner_text("1.0.0")
    test("get_banner_text: contains tagline", "ML-Powered" in text)
    test("get_banner_text: contains version", "1.0.0" in text)


def test_integration():
    """Test that SSRFinder and NeuralForger modules integrate correctly."""
    print("\n[*] Testing SSRFinder + NeuralForger Integration...")

    # Verify NF config extends SSRFinder config
    from config import DEFAULT_PAYLOADS as ssrf_payloads
    test("config: NF imports SSRFinder defaults",
         config.DEFAULT_PAYLOADS == ssrf_payloads)

    # Verify injection markers are a superset
    from config import INJECTION_MARKERS as ssrf_markers
    test("config: NF markers superset of SSRFinder",
         all(m in config.INJECTION_MARKERS for m in ssrf_markers))

    # Verify NF confidence extends SSRFinder confidence
    from confidence_calculator import calculate_confidence
    ssrf_conf, ssrf_reason = calculate_confidence(200, 50.0)
    nf_conf, nf_level, nf_reason = confidence.calculate_injection_confidence(200, 50.0)
    test("confidence: both agree on 200+diff",
         ssrf_conf == "HIGH" and nf_level == "HIGH")

    # Verify auth detection works
    nf_main = _load("neuralforger_main", "neuralforger-main.py")
    test("detect_auth_header: True with auth",
         nf_main.detect_auth_header({"Authorization": "Bearer x"}) is True)
    test("detect_auth_header: False without auth",
         nf_main.detect_auth_header({"Content-Type": "application/json"}) is False)


# ============================================================================
# Run all tests
# ============================================================================

def main():
    print("=" * 72)
    print("NEURAL FORGER - INTEGRATION TEST SUITE")
    print("Testing SSRFinder base + Neural Forger extension")
    print("=" * 72)

    test_detector()
    test_ml_analyzer()
    test_request_parser()
    test_injection()
    test_confidence()
    test_network()
    test_payload_generator()
    test_nf_payload_integration()
    test_cli()
    test_output()
    test_banner()
    test_integration()

    print("\n" + "=" * 72)
    total = passed + failed
    print(f"Results: {passed}/{total} passed, {failed}/{total} failed")

    if failed > 0:
        print(f"\nFailed tests:")
        for err in errors:
            print(f"  - {err}")
        print()

    print("=" * 72)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
