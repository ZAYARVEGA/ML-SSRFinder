#!/usr/bin/env python3
"""
Injection point detection and replacement
"""

from typing import Tuple
from config import INJECTION_MARKERS


def find_injection_point(text: str) -> Tuple[bool, str]:
    """
    Find injection marker in text
    
    Args:
        text: Text to search
    
    Returns:
        Tuple of (found, marker)
    """
    for marker in INJECTION_MARKERS:
        if marker in text:
            return True, marker
    return False, ""


def replace_injection_point(text: str, marker: str, payload: str) -> str:
    """
    Replace injection marker with payload
    
    Args:
        text: Text containing marker
        marker: Injection marker
        payload: Payload to inject
    
    Returns:
        Text with marker replaced
    """
    return text.replace(marker, payload)
