#!/usr/bin/env python3
"""
Response formatting and display functionality
"""

from typing import Dict
from colorama import Fore, Style


def format_response_preview(content: bytes, max_length: int = 500) -> str:
    """
    Format response content for display
    
    Args:
        content: Response content bytes
        max_length: Maximum length to display
    
    Returns:
        Formatted response string
    """
    try:
        text = content.decode('utf-8', errors='ignore')
    except:
        text = str(content)
    
    return text


def display_response_details(status: int, headers: Dict, content: bytes, payload: str):
    """
    Display detailed response information
    
    Args:
        status: HTTP status code
        headers: Response headers
        content: Response content
        payload: Payload that was tested
    """
    print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] RESPONSE DETAILS FOR: {payload}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
    
    # Status
    status_color = Fore.GREEN if 200 <= status < 300 else Fore.YELLOW if 300 <= status < 400 else Fore.RED
    print(f"{status_color}[*] Status Code: {status}{Style.RESET_ALL}\n")
    
    # Headers
    print(f"{Fore.CYAN}[*] Response Headers:{Style.RESET_ALL}")
    for key, value in headers.items():
        print(f"    {Fore.WHITE}{key}: {Style.DIM}{value}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}[*] Response Body ({len(content)} bytes):{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{'â”€'*80}{Style.RESET_ALL}")
    print(format_response_preview(content))
    print(f"{Fore.WHITE}{'â”€'*80}{Style.RESET_ALL}\n")
