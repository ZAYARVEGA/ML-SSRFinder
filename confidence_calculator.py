#!/usr/bin/env python3
"""
Confidence level calculation for SSRF detection
"""

from typing import Tuple, Optional
from colorama import Fore


def calculate_confidence(status_code: Optional[int], size_diff: float) -> Tuple[str, str]:
    """
    Calculate confidence level based on status code and size difference
    
    Args:
        status_code: HTTP status code
        size_diff: Percentage difference in response size
    
    Returns:
        Tuple of (confidence_level, reason)
    """
    if status_code is None:
        return "LOW", "Connection failed"
    
    if status_code == 200 and size_diff > 10:
        return "HIGH", "Status 200 with large response difference"
    
    if status_code in [201, 202, 203, 204, 301, 302, 303, 307, 308] and size_diff > 10:
        return "MEDIUM-HIGH", "Redirect or alternative 2xx status with size difference"
    
    if status_code in [401, 403] and size_diff > 10:
        return "MEDIUM", "Access denied - server processed internal request"
    
    if status_code == 404 and size_diff > 10:
        return "LOW-MEDIUM", "Resource not found - possible internal connection"
    
    if status_code in [500, 502, 503, 504] and size_diff > 10:
        return "LOW", "Server error - possible failed SSRF attempt"
    
    if status_code in [400, 405, 406, 408, 409, 410, 413, 414, 415, 421, 422, 429]:
        return "VERY-LOW", "Client error - likely false positive"
    
    return "NONE", "No significant difference detected"


def get_confidence_color(confidence: str) -> str:
    """
    Return color code based on confidence level
    
    Args:
        confidence: Confidence level string
    
    Returns:
        Colorama color code
    """
    from colorama import Style
    
    colors = {
        "HIGH": Fore.RED,
        "MEDIUM-HIGH": Fore.YELLOW + Style.BRIGHT,
        "MEDIUM": Fore.YELLOW,
        "LOW-MEDIUM": Fore.CYAN,
        "LOW": Fore.CYAN + Style.DIM,
        "VERY-LOW": Fore.WHITE + Style.DIM,
        "NONE": Fore.WHITE
    }
    return colors.get(confidence, Fore.WHITE)
