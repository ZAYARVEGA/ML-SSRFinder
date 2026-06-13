#!/usr/bin/env python3
"""
HTTP request sending functionality
"""

import requests
from typing import Dict, Tuple, Optional


def create_session() -> requests.Session:
    """
    Create and configure a requests session
    
    Returns:
        Configured requests session
    """
    session = requests.Session()
    session.verify = False
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    return session


def send_request(session: requests.Session,
                method: str,
                url: str,
                headers: Dict[str, str],
                body: str = "",
                timeout: int = 5) -> Tuple[Optional[int], Optional[int], Optional[str], Optional[Dict], Optional[bytes]]:
    """
    Send HTTP request and return response details
    
    Args:
        session: Requests session
        method: HTTP method
        url: Target URL
        headers: Request headers
        body: Request body
        timeout: Request timeout
    
    Returns:
        Tuple of (status_code, response_size, error, headers, content)
    """
    try:
        response = session.request(
            method=method,
            url=url,
            headers=headers,
            data=body if body else None,
            timeout=timeout,
            allow_redirects=False
        )
        
        response_size = len(response.content)
        return response.status_code, response_size, None, dict(response.headers), response.content
        
    except requests.exceptions.Timeout:
        return None, None, "Timeout", None, None
    except requests.exceptions.ConnectionError:
        return None, None, "Connection Error", None, None
    except Exception as e:
        return None, None, str(e), None, None
