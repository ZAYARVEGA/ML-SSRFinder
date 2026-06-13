#!/usr/bin/env python3
"""
URL encoding utilities
"""

import urllib.parse


def url_encode_payload(payload: str, encoding_type: str = "none") -> str:
    """
    Apply URL encoding to payload
    
    Args:
        payload: The payload string to encode
        encoding_type: Type of encoding (none, single, double)
    
    Returns:
        Encoded payload string
    """
    if encoding_type == "none":
        return payload
    elif encoding_type == "single":
        return urllib.parse.quote(payload, safe='')
    elif encoding_type == "double":
        encoded_once = urllib.parse.quote(payload, safe='')
        return urllib.parse.quote(encoded_once, safe='')
    else:
        return payload


def add_path_to_payload(payload: str, path: str = None) -> str:
    """
    Add path to payload URL
    
    Args:
        payload: The base payload URL
        path: Path to append
    
    Returns:
        Payload with path appended
    """
    if not path:
        return payload
    
    if not path.startswith('/'):
        path = '/' + path
    
    if '://' in payload:
        if payload.endswith('/'):
            return payload.rstrip('/') + path
        else:
            return payload + path
    else:
        return payload + path
