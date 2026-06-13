#!/usr/bin/env python3
"""
Raw HTTP request parsing functionality
"""

import sys
from typing import Dict, Tuple
from colorama import Fore, Style
from config import SUPPORTED_METHODS


def parse_raw_request(request_file: str) -> Tuple[str, str, Dict[str, str], str, str]:
    """
    Parse raw HTTP request from file
    
    Args:
        request_file: Path to request file
    
    Returns:
        Tuple of (method, url, headers, body, host)
    """
    try:
        with open(request_file, 'r') as f:
            content = f.read()
        
        lines = content.split('\n')
        request_line = lines[0].strip()
        parts = request_line.split(' ')
        
        if len(parts) < 2:
            raise ValueError("Invalid request line format")
        
        method = parts[0].upper()
        path = parts[1]
        
        if method not in SUPPORTED_METHODS:
            print(f"{Fore.YELLOW}[!] Warning: Method '{method}' is not in supported methods list{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Attempting to continue anyway...{Style.RESET_ALL}\n")
        
        headers = {}
        body = ""
        body_start = False
        host = ""
        
        for line in lines[1:]:
            if not body_start:
                if line.strip() == "":
                    body_start = True
                    continue
                
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
                    
                    if key.strip().lower() == 'host':
                        host = value.strip()
            else:
                body += line + '\n'
        
        body = body.strip()
        
        if host:
            if '://' in path:
                url = path
            else:
                scheme = "https" if ':443' in host or host.endswith(':443') else "http"
                url = f"{scheme}://{host}{path}"
        else:
            raise ValueError("Host header not found in request")
        
        return method, url, headers, body, host
        
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Error: Request file '{request_file}' not found{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Error parsing request file: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
