#!/usr/bin/env python3
"""
Neural Forger - Configuration and Constants (Extension)

Extends SSRFinder's base configuration with ML-specific parameters
and Neural Forger tool metadata. Imports all base constants from
SSRFinder's config module.
"""

# Import base SSRFinder configuration
from config import (
    VERSION as SSRFINDER_VERSION,
    INJECTION_MARKERS as BASE_INJECTION_MARKERS,
    SUPPORTED_METHODS as BASE_SUPPORTED_METHODS,
    DEFAULT_PORTS,
    DEFAULT_PAYLOADS,
)

# Tool metadata
VERSION = "1.0.0"
TOOL_NAME = "Neural Forger"
TOOL_DESCRIPTION = "ML-Powered SSRF Detection Framework"
AUTHOR = "Security Research Team"

# Extended HTTP methods (superset of SSRFinder's)
SUPPORTED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

# Extended injection markers (superset of SSRFinder's)
INJECTION_MARKERS = ["SSRF", "***", "INJECT", "FUZZ"]

# HTTP configuration
DEFAULT_TIMEOUT = 5
DEFAULT_THREADS = 1
DEFAULT_USER_AGENT = f"NeuralForger/{VERSION}"

# ML configuration
ML_CONFIDENCE_THRESHOLD = 70
ML_WEIGHT = 0.30
INJECTION_WEIGHT = 0.70

# Payload strategy options
PAYLOAD_STRATEGY_ML = "ml-recommended"
PAYLOAD_STRATEGY_ALL = "all"
PAYLOAD_STRATEGY_CUSTOM = "custom"
PAYLOAD_STRATEGY_ML_ONLY = "ml-only"
DEFAULT_PAYLOAD_STRATEGY = PAYLOAD_STRATEGY_ML

# Output format options
OUTPUT_FORMAT_TEXT = "text"
OUTPUT_FORMAT_JSON = "json"
OUTPUT_FORMAT_XML = "xml"

# Exit codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_VULNERABLE = 2

# Verbosity levels
VERBOSITY_QUIET = 0
VERBOSITY_DEFAULT = 1
VERBOSITY_VERBOSE = 2

# Confidence level thresholds (numeric)
CONFIDENCE_CRITICAL = 90.0
CONFIDENCE_HIGH = 75.0
CONFIDENCE_MEDIUM = 50.0
CONFIDENCE_LOW = 25.0

# Status indicators (no unicode, professional style)
INDICATOR_INFO = "[*]"
INDICATOR_SUCCESS = "[+]"
INDICATOR_FAIL = "[-]"
INDICATOR_WARNING = "[!]"
