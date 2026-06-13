#!/usr/bin/env python3
"""
IP range and port parsing utilities
"""

import sys
import ipaddress
from typing import List
from colorama import Fore, Style


def parse_ip_range(ip_range_str: str) -> List[str]:
    """
    Parse IP range string and return list of IP addresses
    
    Args:
        ip_range_str: IP range string (e.g., "192.168.1.1-254")
    
    Returns:
        List of IP addresses
    """
    try:
        if '-' not in ip_range_str:
            ipaddress.ip_address(ip_range_str)
            return [ip_range_str]
        
        parts = ip_range_str.split('-')
        if len(parts) != 2:
            raise ValueError("Invalid IP range format")
        
        start_ip = parts[0].strip()
        end_part = parts[1].strip()
        
        if '.' in end_part:
            end_ip = end_part
        else:
            start_octets = start_ip.split('.')
            if len(start_octets) != 4:
                raise ValueError("Invalid IP format")
            start_octets[3] = end_part
            end_ip = '.'.join(start_octets)
        
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
        
        if start > end:
            raise ValueError("Start IP must be less than or equal to end IP")
        
        ip_list = []
        current = int(start)
        end_int = int(end)
        
        while current <= end_int:
            ip_list.append(str(ipaddress.IPv4Address(current)))
            current += 1
        
        return ip_list
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error parsing IP range '{ip_range_str}': {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Supported formats: 192.168.1.1-254, 192.168.1.5{Style.RESET_ALL}")
        sys.exit(1)


def parse_ports(ports_str: str) -> List[int]:
    """
    Parse port string and return list of ports
    
    Args:
        ports_str: Port string (e.g., "80,443,8000-9000")
    
    Returns:
        List of port numbers
    """
    try:
        ports = []
        parts = ports_str.split(',')
        
        for part in parts:
            part = part.strip()
            
            if '-' in part:
                start, end = part.split('-')
                start_port = int(start.strip())
                end_port = int(end.strip())
                
                if start_port > end_port:
                    raise ValueError(f"Start port {start_port} must be <= end port {end_port}")
                
                if start_port < 1 or end_port > 65535:
                    raise ValueError(f"Ports must be between 1 and 65535")
                
                ports.extend(range(start_port, end_port + 1))
            else:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Port {port} must be between 1 and 65535")
                ports.append(port)
        
        return sorted(list(set(ports)))
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error parsing ports '{ports_str}': {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
