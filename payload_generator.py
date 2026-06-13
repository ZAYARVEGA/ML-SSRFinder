#!/usr/bin/env python3
"""
Payload generation functionality
"""

import sys
from typing import List, Optional
from colorama import Fore, Style
from config import DEFAULT_PAYLOADS, DEFAULT_PORTS
from network_parser import parse_ip_range, parse_ports
from url_encoding import add_path_to_payload, url_encode_payload


def load_payloads_from_file(wordlist_path: str) -> List[str]:
    """
    Load payloads from a wordlist file
    
    Args:
        wordlist_path: Path to wordlist file
    
    Returns:
        List of payloads
    """
    try:
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            payloads = []
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    payloads.append(line)
            
            if not payloads:
                print(f"{Fore.RED}[!] Error: Wordlist is empty{Style.RESET_ALL}")
                sys.exit(1)
            
            print(f"{Fore.GREEN}[+] Loaded {len(payloads)} payloads from wordlist{Style.RESET_ALL}")
            return payloads
            
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Error: Wordlist file not found: {wordlist_path}{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Error reading wordlist: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)


def generate_payloads(single_url: Optional[str] = None,
                     single_ip: Optional[str] = None,
                     wordlist: Optional[str] = None,
                     ip_range: Optional[str] = None,
                     ports: Optional[str] = None,
                     path: Optional[str] = None,
                     encode: str = "none") -> List[str]:
    """
    Generate SSRF payloads based on provided options
    
    Args:
        single_url: Single URL to test
        single_ip: Single IP to test
        wordlist: Path to wordlist file
        ip_range: IP range string
        ports: Ports string
        path: Path to append
        encode: Encoding type
    
    Returns:
        List of generated payloads
    """
    # If single URL provided, use only that
    if single_url:
        base_payloads = [single_url]
        print(f"{Fore.GREEN}[+] Using single URL: {single_url}{Style.RESET_ALL}")
    # If single IP provided
    elif single_ip:
        base_payloads = []
        
        if ports:
            port_list = parse_ports(ports)
        else:
            port_list = DEFAULT_PORTS
        
        print(f"{Fore.GREEN}[+] Generating payloads for IP {single_ip} with {len(port_list)} ports{Style.RESET_ALL}")
        
        for port in port_list:
            base_payloads.append(f"http://{single_ip}:{port}")
    elif wordlist:
        base_payloads = load_payloads_from_file(wordlist)
    elif ip_range:
        base_payloads = []
        ips = parse_ip_range(ip_range)
        
        if ports:
            port_list = parse_ports(ports)
        else:
            port_list = DEFAULT_PORTS
        
        print(f"{Fore.GREEN}[+] Generating payloads for {len(ips)} IPs and {len(port_list)} ports ({len(ips) * len(port_list)} total combinations){Style.RESET_ALL}")
        
        for ip in ips:
            for port in port_list:
                base_payloads.append(f"http://{ip}:{port}")
    else:
        # Default payloads
        base_payloads = DEFAULT_PAYLOADS.copy()
        
        if ports:
            port_list = parse_ports(ports)
            enhanced_payloads = []
            
            for payload in base_payloads:
                if '://' in payload:
                    scheme, rest = payload.split('://', 1)
                    if '/' in rest:
                        host, path_part = rest.split('/', 1)
                        path_part = '/' + path_part
                    else:
                        host = rest
                        path_part = ''
                    
                    if ':' in host and not host.startswith('['):
                        host = host.split(':')[0]
                    
                    for port in port_list:
                        enhanced_payloads.append(f"{scheme}://{host}:{port}{path_part}")
            
            if enhanced_payloads:
                print(f"{Fore.GREEN}[+] Enhanced {len(base_payloads)} default payloads with {len(port_list)} custom ports ({len(enhanced_payloads)} total){Style.RESET_ALL}")
                base_payloads = enhanced_payloads
    
    # Apply path if specified (unless using single URL which already has path)
    if path and not single_url:
        print(f"{Fore.GREEN}[+] Adding path '{path}' to all payloads{Style.RESET_ALL}")
        base_payloads = [add_path_to_payload(p, path) for p in base_payloads]
    
    # Apply encoding if specified
    if encode != "none":
        encoding_names = {"single": "Single URL encoding", "double": "Double URL encoding"}
        print(f"{Fore.GREEN}[+] Applying {encoding_names.get(encode, encode)} to all payloads{Style.RESET_ALL}")
        base_payloads = [url_encode_payload(p, encode) for p in base_payloads]
    
    return base_payloads
