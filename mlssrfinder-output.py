#!/usr/bin/env python3
"""
ML-SSRFinder - Professional Output Formatter

Handles all terminal output, file output, and structured format generation
(text, JSON, XML). Follows professional pentesting tool conventions with
[*], [+], [-], [!] status indicators.
"""

import json
import sys
import os
import importlib.util
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, TextIO

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class _Stub:
        def __getattr__(self, _):
            return ""
    Fore = Style = _Stub()

# Import config
_cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mlssrfinder-config.py")
_spec = importlib.util.spec_from_file_location("mlssrfinder_config", _cfg_path)
_cfg_mod = importlib.util.module_from_spec(_spec)
if "mlssrfinder_config" not in sys.modules:
    sys.modules["mlssrfinder_config"] = _cfg_mod
    _spec.loader.exec_module(_cfg_mod)
else:
    _cfg_mod = sys.modules["mlssrfinder_config"]

INDICATOR_INFO = _cfg_mod.INDICATOR_INFO
INDICATOR_SUCCESS = _cfg_mod.INDICATOR_SUCCESS
INDICATOR_FAIL = _cfg_mod.INDICATOR_FAIL
INDICATOR_WARNING = _cfg_mod.INDICATOR_WARNING


class OutputFormatter:
    """
    Professional output formatter for ML-SSRFinder.

    Supports text, JSON, and XML output formats with optional file output
    and configurable verbosity levels.
    """

    def __init__(
        self,
        verbosity: int = 1,
        output_format: str = "text",
        output_file: Optional[str] = None,
        use_color: bool = True,
    ):
        """
        Initialize the output formatter.

        Args:
            verbosity: 0=quiet, 1=default, 2=verbose.
            output_format: Output format ('text', 'json', 'xml').
            output_file: Path to output file (optional).
            use_color: Whether to use terminal colors.
        """
        self.verbosity = verbosity
        self.output_format = output_format
        self.output_file = output_file
        self.use_color = use_color and HAS_COLOR
        self._file_handle: Optional[TextIO] = None
        self._collected_results: List[Dict[str, Any]] = []

    def open_output_file(self) -> None:
        """Open the output file for writing."""
        if self.output_file:
            try:
                self._file_handle = open(self.output_file, "w", encoding="utf-8")
            except Exception as exc:
                self.error(f"Cannot open output file: {exc}")

    def close_output_file(self) -> None:
        """Close the output file and write structured output if applicable."""
        if self._file_handle:
            if self.output_format == "json":
                json.dump(self._collected_results, self._file_handle, indent=2)
            elif self.output_format == "xml":
                self._file_handle.write(self._generate_xml())
            self._file_handle.close()
            self._file_handle = None

    # ------------------------------------------------------------------
    # Core print methods
    # ------------------------------------------------------------------

    def info(self, message: str) -> None:
        """Print informational message [*]."""
        if self.verbosity >= 1:
            if self.use_color:
                print(f"{Fore.CYAN}{INDICATOR_INFO} {message}{Style.RESET_ALL}")
            else:
                print(f"{INDICATOR_INFO} {message}")
            self._write_to_file(f"{INDICATOR_INFO} {message}")

    def success(self, message: str) -> None:
        """Print success message [+]."""
        if self.use_color:
            print(f"{Fore.GREEN}{INDICATOR_SUCCESS} {message}{Style.RESET_ALL}")
        else:
            print(f"{INDICATOR_SUCCESS} {message}")
        self._write_to_file(f"{INDICATOR_SUCCESS} {message}")

    def fail(self, message: str) -> None:
        """Print failure message [-]."""
        if self.use_color:
            print(f"{Fore.RED}{INDICATOR_FAIL} {message}{Style.RESET_ALL}")
        else:
            print(f"{INDICATOR_FAIL} {message}")
        self._write_to_file(f"{INDICATOR_FAIL} {message}")

    def warning(self, message: str) -> None:
        """Print warning message [!]."""
        if self.use_color:
            print(f"{Fore.YELLOW}{INDICATOR_WARNING} {message}{Style.RESET_ALL}")
        else:
            print(f"{INDICATOR_WARNING} {message}")
        self._write_to_file(f"{INDICATOR_WARNING} {message}")

    def error(self, message: str) -> None:
        """Print error message [!] to stderr."""
        if self.use_color:
            print(f"{Fore.RED}{INDICATOR_WARNING} Error: {message}{Style.RESET_ALL}", file=sys.stderr)
        else:
            print(f"{INDICATOR_WARNING} Error: {message}", file=sys.stderr)

    def verbose(self, message: str) -> None:
        """Print message only in verbose mode."""
        if self.verbosity >= 2:
            if self.use_color:
                print(f"{Style.DIM}    {message}{Style.RESET_ALL}")
            else:
                print(f"    {message}")
            self._write_to_file(f"    {message}")

    def plain(self, message: str) -> None:
        """Print undecorated message."""
        print(message)
        self._write_to_file(message)

    def separator(self, char: str = "=", width: int = 72) -> None:
        """Print a separator line."""
        line = char * width
        if self.use_color:
            print(f"{Style.DIM}{line}{Style.RESET_ALL}")
        else:
            print(line)
        self._write_to_file(line)

    def blank(self) -> None:
        """Print a blank line."""
        print()
        self._write_to_file("")

    # ------------------------------------------------------------------
    # ML Inspection output
    # ------------------------------------------------------------------

    def print_ml_analysis(self, ml_result: Any) -> None:
        """
        Print ML analysis results in professional format.

        Args:
            ml_result: MLResult object from the ML analyzer.
        """
        self.blank()
        self.separator()
        self.plain("ML ANALYSIS RESULTS")
        self.separator()
        self.blank()

        # Vulnerability probability
        conf = ml_result.confidence
        risk = ml_result.risk_level

        if self.use_color:
            color = Fore.RED if conf >= 70 else Fore.YELLOW if conf >= 50 else Fore.GREEN
            print(f"  Vulnerability Probability: {color}{conf}%{Style.RESET_ALL}")
            risk_color = Fore.RED if risk in ("CRITICAL", "HIGH") else Fore.YELLOW if risk == "MEDIUM" else Fore.GREEN
            print(f"  Risk Level: {risk_color}{risk}{Style.RESET_ALL}")
        else:
            print(f"  Vulnerability Probability: {conf}%")
            print(f"  Risk Level: {risk}")
        self._write_to_file(f"  Vulnerability Probability: {conf}%")
        self._write_to_file(f"  Risk Level: {risk}")

        # Analysis time
        self.verbose(f"Analysis time: {ml_result.analysis_time_ms:.1f}ms")

        # Parameters
        if ml_result.parameters:
            self.blank()
            self.plain("  SUSPICIOUS PARAMETERS IDENTIFIED:")
            self.blank()
            for param in ml_result.parameters:
                if self.use_color:
                    conf_color = Fore.RED if param.confidence >= 70 else Fore.YELLOW if param.confidence >= 40 else Fore.WHITE
                    print(f"  Parameter: {Fore.WHITE}{param.name}{Style.RESET_ALL}")
                    print(f"    Location: {param.location}")
                    print(f"    Confidence: {conf_color}{param.confidence:.0f}%{Style.RESET_ALL}")
                    print(f"    Reason: {Style.DIM}{param.reason}{Style.RESET_ALL}")
                else:
                    print(f"  Parameter: {param.name}")
                    print(f"    Location: {param.location}")
                    print(f"    Confidence: {param.confidence:.0f}%")
                    print(f"    Reason: {param.reason}")
                self._write_to_file(f"  Parameter: {param.name}")
                self._write_to_file(f"    Location: {param.location}")
                self._write_to_file(f"    Confidence: {param.confidence:.0f}%")
                self._write_to_file(f"    Reason: {param.reason}")
                self.blank()

        # Features (verbose only)
        if self.verbosity >= 2 and ml_result.features:
            self.plain("  ML FEATURES DETECTED:")
            for feat in ml_result.features:
                direction = "+" if feat["contribution"] == "positive" else "-"
                self.verbose(f"{direction}{abs(feat['weight']):.2f} {feat['name']}: {feat['description']}")
            self.blank()

        # Recommended payloads
        if ml_result.payloads:
            self.plain("  RECOMMENDED PAYLOADS (by dataset success rate):")
            self.blank()
            for idx, rec in enumerate(ml_result.payloads[:5], 1):
                priority = rec.get("priority", "")
                success = rec.get("success_rate", 0)
                payload = rec.get("payload", "")
                if self.use_color:
                    pri_color = Fore.RED if priority == "CRITICAL" else Fore.YELLOW if priority == "HIGH" else Fore.WHITE
                    print(f"  {idx}. {payload}")
                    print(f"     Priority: {pri_color}{priority}{Style.RESET_ALL} | Success Rate: {success}%")
                else:
                    print(f"  {idx}. {payload}")
                    print(f"     Priority: {priority} | Success Rate: {success}%")
                self._write_to_file(f"  {idx}. {payload}")
                self._write_to_file(f"     Priority: {priority} | Success Rate: {success}%")

        self.blank()

    # ------------------------------------------------------------------
    # Response ML output
    # ------------------------------------------------------------------

    def print_response_ml_results(self, result) -> None:
        """
        Print per-model response ML verdicts with ensemble summary.

        Args:
            result: ResponseMLResult object from ResponseMLAnalyzer.
        """
        if result is None:
            return

        self.blank()
        if self.use_color:
            print(f"{Fore.CYAN}{INDICATOR_INFO} RESPONSE ML ANALYSIS{Style.RESET_ALL}")
        else:
            print(f"{INDICATOR_INFO} RESPONSE ML ANALYSIS")
        self._write_to_file(f"{INDICATOR_INFO} RESPONSE ML ANALYSIS")

        sep_double = "\u2550" * 60
        sep_single = "\u2500" * 60
        self.plain(sep_double)

        # Per-model verdicts
        for verdict in result.verdicts:
            label_upper = verdict.label.upper()
            loo_pct = verdict.accuracy_loo * 100 if verdict.accuracy_loo <= 1.0 else verdict.accuracy_loo

            if self.use_color:
                if verdict.prediction:
                    color = Fore.RED
                else:
                    color = Fore.GREEN

                print(
                    f"  {verdict.model_name:<15}: "
                    f"{color}{label_upper:<8}{Style.RESET_ALL}  "
                    f"(confidence: {verdict.confidence_pct:.1f}%)  "
                    f"[LOO: {loo_pct:.1f}%]"
                )
            else:
                print(
                    f"  {verdict.model_name:<15}: "
                    f"{label_upper:<8}  "
                    f"(confidence: {verdict.confidence_pct:.1f}%)  "
                    f"[LOO: {loo_pct:.1f}%]"
                )

            self._write_to_file(
                f"  {verdict.model_name:<15}: "
                f"{label_upper:<8}  "
                f"(confidence: {verdict.confidence_pct:.1f}%)  "
                f"[LOO: {loo_pct:.1f}%]"
            )

        self.plain(sep_single)

        # Ensemble summary
        ensemble_label = "POSITIVE" if result.ensemble_positive else "NEGATIVE"
        vote_str = f"{result.positive_count}/{result.positive_count + result.negative_count} models"

        if self.use_color:
            if result.ensemble_positive and result.negative_count == 0:
                # Unanimous positive
                ens_color = Fore.LIGHTRED_EX
            elif result.ensemble_positive:
                # Split positive
                ens_color = Fore.YELLOW
            else:
                ens_color = Fore.GREEN

            print(
                f"  Ensemble vote : "
                f"{ens_color}{ensemble_label}{Style.RESET_ALL}  "
                f"({vote_str})"
            )
            print(
                f"  Weighted conf : "
                f"{ens_color}{result.ensemble_confidence:.1f}%{Style.RESET_ALL}"
            )
        else:
            print(f"  Ensemble vote : {ensemble_label}  ({vote_str})")
            print(f"  Weighted conf : {result.ensemble_confidence:.1f}%")

        self._write_to_file(f"  Ensemble vote : {ensemble_label}  ({vote_str})")
        self._write_to_file(f"  Weighted conf : {result.ensemble_confidence:.1f}%")

        self.plain(sep_double)
        self.blank()

    def _print_response_ml_inline(self, result) -> None:
        """
        Print response ML verdicts inline under a payload result.

        Shows each model's full name and SSRF probability on its own line,
        followed by the ensemble summary.
        Only called when the payload is actually being displayed.
        """
        print("    Response ML (SSRF probability):")

        for v in result.verdicts:
            label_upper = v.label.upper()

            if self.use_color:
                color = Fore.RED if v.prediction else Fore.GREEN
                print(f"      {v.model_name:<15}: "
                      f"{color}{v.confidence_pct:.1f}% SSRF  ({label_upper}){Style.RESET_ALL}")
            else:
                print(f"      {v.model_name:<15}: "
                      f"{v.confidence_pct:.1f}% SSRF  ({label_upper})")

            self._write_to_file(
                f"      {v.model_name:<15}: {v.confidence_pct:.1f}% SSRF  ({label_upper})"
            )

        # Ensemble summary
        ensemble_label = "POSITIVE" if result.ensemble_positive else "NEGATIVE"
        vote_str = f"{result.positive_count}/{result.positive_count + result.negative_count}"

        if self.use_color:
            if result.ensemble_positive and result.negative_count == 0:
                ens_color = Fore.LIGHTRED_EX
            elif result.ensemble_positive:
                ens_color = Fore.YELLOW
            else:
                ens_color = Fore.GREEN

            print(f"      {'Ensemble':<15}: "
                  f"{ens_color}{ensemble_label} ({vote_str}) "
                  f"-> {result.ensemble_confidence:.1f}% SSRF{Style.RESET_ALL}")
        else:
            print(f"      {'Ensemble':<15}: "
                  f"{ensemble_label} ({vote_str}) "
                  f"-> {result.ensemble_confidence:.1f}% SSRF")

        self._write_to_file(
            f"      {'Ensemble':<15}: {ensemble_label} ({vote_str}) "
            f"-> {result.ensemble_confidence:.1f}% SSRF"
        )

        # Primary decision source (defaults to the strongest single model).
        decision_mode = getattr(result, 'decision_mode', 'ensemble')
        if decision_mode != 'ensemble':
            dec_positive = getattr(result, 'decision_positive', result.ensemble_positive)
            dec_conf = getattr(result, 'decision_confidence', result.ensemble_confidence)
            dec_label = 'POSITIVE' if dec_positive else 'NEGATIVE'
            if self.use_color:
                dec_color = Fore.RED if dec_positive else Fore.GREEN
                print(f"      {'Decision':<15}: "
                      f"{dec_color}{dec_label} (model: {decision_mode}) "
                      f"-> {dec_conf:.1f}% SSRF{Style.RESET_ALL}")
            else:
                print(f"      {'Decision':<15}: "
                      f"{dec_label} (model: {decision_mode}) "
                      f"-> {dec_conf:.1f}% SSRF")
            self._write_to_file(
                f"      {'Decision':<15}: {dec_label} (model: {decision_mode}) "
                f"-> {dec_conf:.1f}% SSRF"
            )

    def _print_content_findings(self, content_analysis) -> None:
        """
        Print content analysis findings (sensitive data detected in response).
        """
        severity_colors = {
            'CRITICAL': Fore.LIGHTRED_EX,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.WHITE,
        }

        for finding in content_analysis.findings:
            if self.use_color:
                color = severity_colors.get(finding.severity, Fore.WHITE)
                print(f"    {color}[{finding.severity}] {finding.description}{Style.RESET_ALL}")
            else:
                print(f"    [{finding.severity}] {finding.description}")
            self._write_to_file(f"    [{finding.severity}] {finding.description}")

    # ------------------------------------------------------------------
    # Injection test output
    # ------------------------------------------------------------------

    def print_injection_result(
        self,
        index: int,
        total: int,
        payload: str,
        status_code: Optional[int],
        response_size: Optional[int],
        response_time_ms: Optional[float],
        confidence: float,
        confidence_level: str,
        error: Optional[str] = None,
        is_critical: bool = False,
        critical_reason: str = "",
        response_ml_result=None,
        content_analysis=None,
    ) -> None:
        """
        Print a single injection test result.

        Args:
            index: Current test number.
            total: Total number of tests.
            payload: Payload that was tested.
            status_code: HTTP response status code.
            response_size: Response size in bytes.
            response_time_ms: Response time in milliseconds.
            confidence: Numeric confidence score.
            confidence_level: Confidence level string.
            error: Error message if request failed.
            is_critical: Whether this is a critical finding.
            critical_reason: Reason for critical classification.
            response_ml_result: ResponseMLResult object (optional).
            content_analysis: ContentAnalysis object (optional).
        """
        result_data = {
            "index": index,
            "payload": payload,
            "status_code": status_code,
            "response_size": response_size,
            "response_time_ms": round(response_time_ms, 1) if response_time_ms else None,
            "confidence": round(confidence, 1),
            "confidence_level": confidence_level,
            "error": error,
            "is_critical": is_critical,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._collected_results.append(result_data)

        if error:
            if self.verbosity >= 2:
                self.fail(f"Payload: {payload}")
                self.verbose(f"Error: {error}")
            return

        # Check for blocked responses — show as blocked in verbose mode
        if content_analysis and content_analysis.is_blocked and not content_analysis.findings:
            if self.verbosity >= 2:
                if self.use_color:
                    print(f"{Style.DIM}[-] Payload: {payload}{Style.RESET_ALL}")
                    print(f"    {Fore.YELLOW}BLOCKED: {content_analysis.block_reason[:100]}{Style.RESET_ALL}")
                else:
                    print(f"[-] Payload: {payload}")
                    print(f"    BLOCKED: {content_analysis.block_reason[:100]}")
                self._write_to_file(f"[-] Payload: {payload}")
                self._write_to_file(f"    BLOCKED: {content_analysis.block_reason[:100]}")
            return

        # Status determination
        if confidence >= 75.0:
            status_label = "VULNERABLE"
            if is_critical:
                status_label = f"CRITICAL - {critical_reason}"
        elif confidence >= 50.0:
            status_label = "POSSIBLE"
        else:
            status_label = "UNLIKELY"
            if self.verbosity < 2:
                return  # Skip low-confidence in non-verbose mode

        if self.use_color:
            if confidence >= 75.0:
                color = Fore.RED
            elif confidence >= 50.0:
                color = Fore.YELLOW
            else:
                color = Style.DIM

            print(f"{color}{INDICATOR_SUCCESS} Payload: {payload}{Style.RESET_ALL}")
            print(f"    Response: {status_code} ({response_size:,} bytes)")
            print(f"    Response Time: {response_time_ms:.0f}ms")
            print(f"    Confidence Score: {color}{confidence:.1f}%{Style.RESET_ALL}")
            print(f"    Status: {color}{status_label}{Style.RESET_ALL}")
        else:
            print(f"{INDICATOR_SUCCESS} Payload: {payload}")
            print(f"    Response: {status_code} ({response_size:,} bytes)")
            print(f"    Response Time: {response_time_ms:.0f}ms")
            print(f"    Confidence Score: {confidence:.1f}%")
            print(f"    Status: {status_label}")

        self._write_to_file(f"{INDICATOR_SUCCESS} Payload: {payload}")
        self._write_to_file(f"    Response: {status_code} ({response_size:,} bytes)")
        self._write_to_file(f"    Response Time: {response_time_ms:.0f}ms")
        self._write_to_file(f"    Confidence Score: {confidence:.1f}%")
        self._write_to_file(f"    Status: {status_label}")

        # Show Response ML verdicts inline (only for displayed payloads)
        if response_ml_result is not None:
            self._print_response_ml_inline(response_ml_result)

        # Show content analysis findings
        if content_analysis and content_analysis.findings:
            self._print_content_findings(content_analysis)

        print()

    # ------------------------------------------------------------------
    # Summary output
    # ------------------------------------------------------------------

    def print_assessment_summary(
        self,
        vulnerable_count: int,
        total_tested: int,
        ml_confidence: Optional[float],
        best_injection_confidence: float,
        combined_confidence: Optional[float],
        severity: str,
        results: List[Dict[str, Any]],
    ) -> None:
        """
        Print the final assessment summary.

        Args:
            vulnerable_count: Number of confirmed vulnerable payloads.
            total_tested: Total payloads tested.
            ml_confidence: ML prediction confidence.
            best_injection_confidence: Highest injection confidence.
            combined_confidence: Combined weighted confidence.
            severity: Overall severity label.
            results: Full results list.
        """
        self.blank()
        self.separator("=")
        self.plain("FINAL ASSESSMENT")
        self.separator("=")
        self.blank()

        is_vuln = vulnerable_count > 0

        if self.use_color:
            status_color = Fore.RED if is_vuln else Fore.GREEN
            sev_color = Fore.RED if severity in ("CRITICAL", "HIGH") else Fore.YELLOW if severity == "MEDIUM" else Fore.GREEN

            print(f"  Vulnerability Status: {status_color}{'CONFIRMED' if is_vuln else 'NOT DETECTED'}{Style.RESET_ALL}")
            if combined_confidence is not None:
                print(f"  Combined Confidence: {status_color}{combined_confidence:.1f}%{Style.RESET_ALL}")
            print(f"  Severity: {sev_color}{severity}{Style.RESET_ALL}")
            print()
            if ml_confidence is not None:
                ml_accuracy = "CORRECT" if (ml_confidence >= 50 and is_vuln) or (ml_confidence < 50 and not is_vuln) else "INCORRECT"
                ml_color = Fore.GREEN if ml_accuracy == "CORRECT" else Fore.RED
                print(f"  ML Prediction: {ml_confidence:.0f}%")
                print(f"  Injection Confidence: {best_injection_confidence:.1f}%")
                print(f"  ML Prediction Accuracy: {ml_color}{ml_accuracy}{Style.RESET_ALL}")
        else:
            print(f"  Vulnerability Status: {'CONFIRMED' if is_vuln else 'NOT DETECTED'}")
            if combined_confidence is not None:
                print(f"  Combined Confidence: {combined_confidence:.1f}%")
            print(f"  Severity: {severity}")
            print()
            if ml_confidence is not None:
                ml_accuracy = "CORRECT" if (ml_confidence >= 50 and is_vuln) or (ml_confidence < 50 and not is_vuln) else "INCORRECT"
                print(f"  ML Prediction: {ml_confidence:.0f}%")
                print(f"  Injection Confidence: {best_injection_confidence:.1f}%")
                print(f"  ML Prediction Accuracy: {ml_accuracy}")

        self._write_to_file(f"  Vulnerability Status: {'CONFIRMED' if is_vuln else 'NOT DETECTED'}")
        if combined_confidence is not None:
            self._write_to_file(f"  Combined Confidence: {combined_confidence:.1f}%")
        self._write_to_file(f"  Severity: {severity}")

        self.blank()
        self.plain(f"  Statistics:")
        self.plain(f"    Payloads Tested: {total_tested}")
        self.plain(f"    Vulnerable: {vulnerable_count}")
        self.plain(f"    Baseline Comparison: {'Active' if total_tested > 0 else 'N/A'}")
        self.blank()

        # Save notification
        if self.output_file:
            self.success(f"Results saved to: {self.output_file}")

    # ------------------------------------------------------------------
    # Inspection mode follow-up suggestion
    # ------------------------------------------------------------------

    def print_inspect_followup(self, request_file: str, best_param: str) -> None:
        """
        Print follow-up command suggestion after inspection.

        Args:
            request_file: Path to the request file.
            best_param: Best parameter name for injection testing.
        """
        self.blank()
        self.success("Proceed with detailed injection testing using:")
        self.plain(f"    ml-ssrfinder -r {request_file} -p {best_param}")
        self.blank()

    # ------------------------------------------------------------------
    # Progress indicator
    # ------------------------------------------------------------------

    def print_progress(self, current: int, total: int) -> None:
        """Print progress indicator for quiet mode."""
        if self.verbosity == 0:
            pct = int((current / total) * 100) if total > 0 else 0
            sys.stdout.write(f"\r{INDICATOR_INFO} Progress: {current}/{total} ({pct}%)")
            sys.stdout.flush()
            if current == total:
                sys.stdout.write("\n")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write_to_file(self, line: str) -> None:
        """Write a line to the output file if open (text mode)."""
        if self._file_handle and self.output_format == "text":
            self._file_handle.write(line + "\n")

    def _generate_xml(self) -> str:
        """Generate XML output from collected results."""
        lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        lines.append("<mlssrfinder_results>")
        lines.append(f'  <timestamp>{datetime.now(timezone.utc).isoformat()}</timestamp>')
        lines.append(f"  <total_tests>{len(self._collected_results)}</total_tests>")
        for result in self._collected_results:
            lines.append("  <result>")
            for key, value in result.items():
                if value is not None:
                    safe_val = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    lines.append(f"    <{key}>{safe_val}</{key}>")
            lines.append("  </result>")
        lines.append("</mlssrfinder_results>")
        return "\n".join(lines)
