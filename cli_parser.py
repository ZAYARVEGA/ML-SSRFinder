#!/usr/bin/env python3
"""
Command-line argument parsing
"""

import argparse


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure argument parser
    
    Returns:
        Configured ArgumentParser
    """
    parser = argparse.ArgumentParser(
        description='SSRFinder v0.2.5 Beta - SSRF Detection with Single URL/IP Testing and Response Viewing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with default payloads
  python3 ssrfinder.py -r request.txt -p url
  
  # Scan IP range
  python3 ssrfinder.py -r request.txt -p url --ip-range 192.168.1.1-50 -q
  
  # Test a specific IP across multiple ports
  python3 ssrfinder.py -r request.txt -p url --ip 192.168.1.5
  
  # Test a specific URL/payload directly
  python3 ssrfinder.py -r request.txt -p url --single-url "http://192.168.1.5:8080/admin"
  
  # Show HTTP responses for high-confidence findings
  python3 ssrfinder.py -r request.txt -p url --show-response
  python3 ssrfinder.py -r request.txt -p url -s  # Short form
  
  # Investigate a specific finding in detail
  python3 ssrfinder.py -r request.txt -p url --ip 192.168.1.5 -s
  python3 ssrfinder.py -r request.txt -p url --single-url "http://localhost/admin" -s

Workflow - Finding and Investigating SSRF:
  # 1. Initial broad scan to find vulnerable IPs (quiet mode for clean output)
  python3 ssrfinder.py -r request.txt -p url --ip-range 192.168.1.1-50 -q
  
  # 2. Found: 192.168.1.5 returned high confidence
  
  # 3. Investigate that specific IP with all common ports
  python3 ssrfinder.py -r request.txt -p url --ip 192.168.1.5 -s
  
  # 4. Found: Port 8080 is vulnerable
  
  # 5. Deep dive into that specific URL with response viewing
  python3 ssrfinder.py -r request.txt -p url --single-url "http://192.168.1.5:8080/admin" -s
  
  # 6. Analyze the HTTP response to understand what data you can access
        """
    )
    
    parser.add_argument('-r', '--request', help='Raw HTTP request file', type=str)
    parser.add_argument('-u', '--url', help='Target URL with injection marker', type=str)
    parser.add_argument('-p', '--param', help='Parameter name to test', type=str, required=True)
    parser.add_argument('-t', '--timeout', help='Request timeout in seconds (default: 5)', type=int, default=5)
    parser.add_argument('-w', '--wordlist', help='Custom payload wordlist file', type=str, default=None)
    parser.add_argument('--ip-range', help='IP range to test (e.g., 192.168.1.1-254)', type=str, default=None)
    parser.add_argument('--ip', help='Single IP to test across multiple ports', type=str, default=None)
    parser.add_argument('-P', '--port', dest='ports', help='Port(s) to test (e.g., 80,443,8080 or 8000-9000)', type=str, default=None)
    parser.add_argument('--path', help='Path to add to payloads (e.g., /admin)', type=str, default=None)
    parser.add_argument('--encode', help='URL encoding: none, single, double', type=str, default='none', choices=['none', 'single', 'double'])
    parser.add_argument('--single-url', help='Test a single specific URL (e.g., http://192.168.1.5:8080/admin)', type=str, default=None)
    parser.add_argument('--show-response', '-s', help='Show HTTP response content for high-confidence findings', action='store_true')
    parser.add_argument('-q', '--quiet', help='Quiet mode - reduce output', action='store_true')
    
    return parser
