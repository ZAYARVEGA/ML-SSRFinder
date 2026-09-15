#!/usr/bin/env python3
"""
ML-SSRFinder - Command-Line Interface Parser (Extension)

Extends SSRFinder's base CLI with ML-SSRFinder-specific arguments:
ML inspection mode, payload strategies, output formats, proxy support,
and the detailed --manual documentation.

Imports SSRFinder's base arguments and adds ML-SSRFinder extras on top.
"""

import argparse
import sys
import os
import importlib.util

# Import NeuralForger config
_cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mlssrfinder-config.py")
_spec = importlib.util.spec_from_file_location("mlssrfinder_config", _cfg_path)
_cfg_mod = importlib.util.module_from_spec(_spec)
if "mlssrfinder_config" not in sys.modules:
    sys.modules["mlssrfinder_config"] = _cfg_mod
    _spec.loader.exec_module(_cfg_mod)
else:
    _cfg_mod = sys.modules["mlssrfinder_config"]

VERSION = _cfg_mod.VERSION
TOOL_NAME = _cfg_mod.TOOL_NAME


# ============================================================================
# Manual text
# ============================================================================

MANUAL_TEXT = f"""
{TOOL_NAME.upper()} - DETAILED MANUAL
{'=' * 72}

1. INTRODUCTION

   ML-SSRFinder is an extension for SSRFinder that adds machine learning
   enhanced detection methods. It combines statistical analysis of HTTP
   request structure with SSRFinder's injection testing to produce
   high-confidence vulnerability assessments.

   The tool operates in two primary modes:
   - Inspection mode (-i): ML-only analysis without injection
   - Injection mode (-p): Full payload testing with ML augmentation

   ML-SSRFinder reuses SSRFinder's core modules (request parsing,
   payload generation, network utilities) and extends them with:
   - ML-based pre-analysis and parameter discovery
   - Combined ML + injection confidence scoring
   - Professional output formatting (text, JSON, XML)
   - Proxy support and response timing analysis

2. OPERATIONAL METHODOLOGY

   2.1 Machine Learning Analysis

   The ML component analyzes HTTP request structure including parameter
   names, endpoint patterns, authentication requirements, and protocol
   usage. Analysis is performed without payload injection, providing
   rapid vulnerability assessment suitable for reconnaissance phases.

   Feature weights are derived from a curated 40-example training dataset
   of confirmed SSRF vulnerabilities. The model evaluates:
   - Parameter name indicators (url, webhook, redirect, callback, etc.)
   - Endpoint pattern analysis (/api/, /fetch, /proxy, /webhook)
   - Authentication presence (reduces exploitation surface)
   - HTTP method and protocol characteristics

   2.2 Parameter Discovery

   ML-SSRFinder automatically discovers injectable parameters from:
   - URL query string parameters
   - Form-encoded body parameters
   - JSON body fields
   Each parameter is scored individually for SSRF likelihood.

   2.3 Injection Testing

   Following ML analysis, the tool performs systematic payload injection
   using SSRFinder's core engine enhanced with ML-optimized payloads
   ranked by historical success rates.

   2.4 Confidence Scoring

   The confidence engine combines two independent scores:
   - ML prediction confidence (weight: 30%)
   - Injection test confidence (weight: 70%)

   When --response-ml is active (active mode), the weights shift:
   - Response ML confidence (weight: 60%)
   - Injection test confidence (weight: 30%)
   - Request ML confidence (weight: 10%)

3. USAGE PATTERNS

   3.1 Reconnaissance (Inspection Only)

       ml-ssrfinder -r captured_request.txt -i

   3.2 Targeted Injection Testing

       ml-ssrfinder -r captured_request.txt -p url

   3.3 Direct URL Testing

       ml-ssrfinder -u "http://target.com/api/fetch?url=SSRF" -p url

   3.4 IP Range Scanning

       ml-ssrfinder -r request.txt -p url --ip-range 192.168.1.1-254

   3.5 Single IP Port Scan

       ml-ssrfinder -r request.txt -p url --ip 192.168.1.5

   3.6 Payload Strategy Selection

       ml-ssrfinder -r request.txt -p url --payload-strategy ml-only
       ml-ssrfinder -r request.txt -p url --payload-strategy all

4. CONFIDENCE LEVELS

   CRITICAL  (90-100%): Confirmed exploitation with high certainty
   HIGH      (75-89%):  Strong indicators of vulnerability
   MEDIUM    (50-74%):  Moderate indicators requiring manual verification
   LOW       (25-49%):  Weak indicators, likely false positive
   INFO      (0-24%):   No significant indicators detected

5. EXIT CODES

   0  - Execution completed successfully, no vulnerabilities found
   1  - Error during execution
   2  - Vulnerability confirmed (at least one HIGH confidence result)

{'=' * 72}
ML-SSRFinder v{VERSION} (SSRFinder Extension)
"""


# ============================================================================
# Argument parser
# ============================================================================

class NeuralForgerHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Custom help formatter with wider output."""
    def __init__(self, prog, indent_increment=2, max_help_position=36, width=80):
        super().__init__(prog, indent_increment, max_help_position, width)


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create the ML-SSRFinder argument parser.

    Includes all SSRFinder base arguments plus ML-SSRFinder extensions:
    --inspect, --payload-strategy, --confidence-threshold, --proxy,
    --threads, --format, --output, --manual, --verbose.

    Returns:
        Configured argparse.ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="ml-ssrfinder",
        description=(
            f"{TOOL_NAME} - ML-Powered SSRF Detection Framework\n"
            f"Version {VERSION} (SSRFinder Extension)\n"
            "\n"
            "DESCRIPTION:\n"
            "  ML-SSRFinder extends SSRFinder with machine learning\n"
            "  analysis for enhanced SSRF vulnerability detection.\n"
            "  It operates in two stages: ML-based pre-analysis and\n"
            "  detailed injection testing using SSRFinder's core engine.\n"
        ),
        formatter_class=NeuralForgerHelpFormatter,
        epilog=(
            "Use --manual for detailed documentation and usage examples.\n"
            f"{TOOL_NAME} v{VERSION}"
        ),
        add_help=True,
    )

    # -- Required arguments group (same as SSRFinder) --
    required = parser.add_argument_group("REQUIRED ARGUMENTS")
    required.add_argument(
        "-r", "--request",
        metavar="FILE",
        type=str,
        help="Specify HTTP request file for analysis.",
    )

    # -- Operation modes (extends SSRFinder with -i/--inspect) --
    modes = parser.add_argument_group("OPERATION MODES")
    modes.add_argument(
        "-i", "--inspect",
        action="store_true",
        help=(
            "Execute ML pre-analysis mode. Analyzes request structure\n"
            "and identifies potentially vulnerable parameters without\n"
            "performing injection attacks."
        ),
    )
    modes.add_argument(
        "-p", "--parameter",
        metavar="NAME",
        type=str,
        dest="param",
        help=(
            "Execute injection testing on specified parameter. Combines\n"
            "ML recommendations with comprehensive payload testing."
        ),
    )
    modes.add_argument(
        "-u", "--url",
        metavar="URL",
        type=str,
        help=(
            "Direct URL testing (alternative to -r). The URL must\n"
            "contain an injection marker (SSRF, ***, INJECT, or FUZZ)."
        ),
    )

    # -- Payload options (SSRFinder base + NF extensions) --
    payloads = parser.add_argument_group("PAYLOAD OPTIONS")
    payloads.add_argument(
        "--payload-strategy",
        metavar="STRATEGY",
        type=str,
        default="ml-recommended",
        choices=["ml-recommended", "all", "ml-only", "custom"],
        help=(
            "Payload selection strategy. Options: ml-recommended (default),\n"
            "all, ml-only, custom (requires --wordlist)."
        ),
    )
    payloads.add_argument(
        "-w", "--wordlist",
        metavar="FILE",
        type=str,
        help="Custom payload wordlist file.",
    )
    payloads.add_argument(
        "--ip-range",
        metavar="RANGE",
        type=str,
        help="IP range to test (e.g., 192.168.1.1-254).",
    )
    payloads.add_argument(
        "--ip",
        metavar="ADDRESS",
        type=str,
        help="Single IP to test across multiple ports.",
    )
    payloads.add_argument(
        "--single-url",
        metavar="URL",
        type=str,
        help="Test a single specific URL payload.",
    )
    payloads.add_argument(
        "-P", "--port",
        dest="ports",
        metavar="PORTS",
        type=str,
        help="Port(s) to test (e.g., 80,443,8080 or 8000-9000).",
    )
    payloads.add_argument(
        "--path",
        metavar="PATH",
        type=str,
        help="Path to append to generated payloads (e.g., /admin).",
    )
    payloads.add_argument(
        "--encode",
        metavar="TYPE",
        type=str,
        default="none",
        choices=["none", "single", "double"],
        help="URL encoding: none (default), single, double.",
    )
    payloads.add_argument(
        '--response-ml',
        action='store_true',
        default=False,
        dest='response_ml',
        help=(
            'Enable ML analysis of HTTP responses after payload injection.\n'
            'Runs SVM, XGBoost, and Random Forest on each response to\n'
            'confirm SSRF. Requires -p (injection mode). Active scan.'
        ),
    )
    payloads.add_argument(
        '--response-decision',
        metavar='SOURCE',
        type=str,
        default='svm',
        choices=['svm', 'ensemble'],
        dest='response_decision',
        help=(
            'Which response model decides the verdict when --response-ml is\n'
            'active: svm (default, strongest single model) or ensemble\n'
            '(majority vote of the three models). All three models are\n'
            'always run and reported regardless of this choice.'
        ),
    )

    # -- Advanced options (NF extensions) --
    advanced = parser.add_argument_group("ADVANCED OPTIONS")
    advanced.add_argument(
        "--confidence-threshold",
        metavar="N",
        type=int,
        default=70,
        help="Minimum ML confidence to proceed with injection (default: 70).",
    )
    advanced.add_argument(
        "-t", "--timeout",
        metavar="SECONDS",
        type=int,
        default=5,
        help="Request timeout in seconds (default: 5).",
    )
    advanced.add_argument(
        "--threads",
        metavar="N",
        type=int,
        default=1,
        help="Concurrent threads for injection testing (default: 1).",
    )
    advanced.add_argument(
        "--proxy",
        metavar="URL",
        type=str,
        help="HTTP/HTTPS proxy URL.",
    )

    # -- Output options (NF extensions) --
    output = parser.add_argument_group("OUTPUT OPTIONS")
    output.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output with ML reasoning and detailed responses.",
    )
    output.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Minimal output (results only).",
    )
    output.add_argument(
        "-o", "--output",
        metavar="FILE",
        type=str,
        help="Save results to file.",
    )
    output.add_argument(
        "--format",
        metavar="FORMAT",
        type=str,
        default="text",
        choices=["text", "json", "xml"],
        help="Output format: text (default), json, xml.",
    )
    output.add_argument(
        "--show-response",
        "-s",
        action="store_true",
        help="Show HTTP response content for high-confidence findings.",
    )

    # -- Information --
    info = parser.add_argument_group("INFORMATION")
    info.add_argument(
        "-m", "--manual",
        action="store_true",
        help="Display detailed manual with usage examples.",
    )
    info.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} v{VERSION}",
    )

    return parser


def print_manual() -> None:
    """Display the detailed manual and exit."""
    print(MANUAL_TEXT)
    sys.exit(0)


def validate_arguments(args: argparse.Namespace) -> None:
    """
    Validate parsed arguments for logical consistency.

    Args:
        args: Parsed argument namespace.

    Raises:
        SystemExit: If arguments are invalid.
    """
    errors = []

    if args.manual:
        return

    if not args.request and not args.url:
        if not args.inspect:
            errors.append("Either -r/--request or -u/--url must be specified.")

    if args.request and args.url:
        errors.append("Cannot use both -r/--request and -u/--url simultaneously.")

    if not args.inspect and not args.param:
        if args.request or args.url:
            errors.append("Either -i/--inspect or -p/--parameter must be specified.")

    if args.verbose and args.quiet:
        errors.append("Cannot use both -v/--verbose and -q/--quiet simultaneously.")

    exclusive = [args.wordlist, args.ip_range, args.single_url, args.ip]
    if sum(bool(x) for x in exclusive) > 1:
        errors.append("Only one of --wordlist, --ip-range, --ip, or --single-url can be used.")

    if args.payload_strategy == "custom" and not args.wordlist:
        errors.append("--payload-strategy custom requires --wordlist.")

    # Validate --response-ml requires injection mode
    if hasattr(args, 'response_ml') and args.response_ml and not args.param:
        print(
            "[!] --response-ml requires injection mode (-p PARAMETER).\n"
            "    Response ML analyzes server responses — it needs payloads to be injected first.\n"
            "    For passive analysis only, use -i (inspect) without --response-ml.",
            file=sys.stderr,
        )
        sys.exit(1)

    if errors:
        print(f"[!] Argument validation failed:", file=sys.stderr)
        for error in errors:
            print(f"    {error}", file=sys.stderr)
        print(f"\nUse --help for usage information.", file=sys.stderr)
        sys.exit(1)
