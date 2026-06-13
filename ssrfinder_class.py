#!/usr/bin/env python3
"""
Main SSRFinder class
"""

import sys
from typing import Optional, List, Dict
from colorama import Fore, Style
from request_sender import create_session, send_request
from request_parser import parse_raw_request
from injection_handler import find_injection_point, replace_injection_point
from payload_generator import generate_payloads
from confidence_calculator import calculate_confidence, get_confidence_color
from response_formatter import display_response_details
from summary_printer import print_summary


class SSRFinder:
    """Main SSRF detection tool class"""
    
    def __init__(self, timeout: int = 5, wordlist: Optional[str] = None, 
                 ip_range: Optional[str] = None, ports: Optional[str] = None,
                 verbose: bool = True, path: Optional[str] = None,
                 encode: str = "none", show_response: bool = False,
                 single_url: Optional[str] = None, single_ip: Optional[str] = None):
        self.timeout = timeout
        self.wordlist = wordlist
        self.ip_range = ip_range
        self.ports = ports
        self.verbose = verbose
        self.path = path
        self.encode = encode.lower()
        self.show_response = show_response
        self.single_url = single_url
        self.single_ip = single_ip
        self.session = create_session()
    
    def run_from_request_file(self, request_file: str, param: str):
        """Run SSRF detection from raw request file"""
        if self.verbose:
            print(f"{Fore.CYAN}[*] Parsing request file...{Style.RESET_ALL}")
        
        method, url, headers, body, host = parse_raw_request(request_file)
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Method: {method}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] URL: {url}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Host: {host}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Parameter: {param}{Style.RESET_ALL}")
            if self.single_url:
                print(f"{Fore.CYAN}[*] Single URL Mode: {self.single_url}{Style.RESET_ALL}")
            if self.single_ip:
                print(f"{Fore.CYAN}[*] Single IP Mode: {self.single_ip}{Style.RESET_ALL}")
            if self.path:
                print(f"{Fore.CYAN}[*] Path: {self.path}{Style.RESET_ALL}")
            if self.encode != "none":
                encoding_display = {"single": "Single", "double": "Double"}
                print(f"{Fore.CYAN}[*] Encoding: {encoding_display.get(self.encode, 'None')}{Style.RESET_ALL}")
            if self.show_response:
                print(f"{Fore.CYAN}[*] Show Response: Enabled{Style.RESET_ALL}")
            if body:
                print(f"{Fore.CYAN}[*] Body: {body[:100]}{'...' if len(body) > 100 else ''}{Style.RESET_ALL}")
            print()
        
        full_request = url + '\n' + '\n'.join([f"{k}: {v}" for k, v in headers.items()])
        if body:
            full_request += '\n' + body
        
        found, marker = find_injection_point(full_request)
        
        if not found:
            print(f"{Fore.RED}[!] Error: Injection marker (SSRF or ***) not found in request{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Please mark the injection point with 'SSRF' or '***'{Style.RESET_ALL}")
            sys.exit(1)
        
        if self.verbose:
            print(f"{Fore.GREEN}[+] Injection marker '{marker}' found{Style.RESET_ALL}\n")
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Establishing baseline response...{Style.RESET_ALL}")
        
        baseline_url = replace_injection_point(url, marker, "")
        baseline_headers = {k: replace_injection_point(v, marker, "") for k, v in headers.items()}
        baseline_body = replace_injection_point(body, marker, "") if body else ""
        
        baseline_status, baseline_size, baseline_error, _, _ = send_request(
            self.session, method, baseline_url, baseline_headers, baseline_body, self.timeout
        )
        
        if baseline_error:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Baseline request failed: {baseline_error}{Style.RESET_ALL}")
            baseline_size = 0
        else:
            if self.verbose:
                print(f"{Fore.GREEN}[+] Baseline established - Status: {baseline_status}, Size: {baseline_size} bytes{Style.RESET_ALL}")
        
        if self.verbose:
            print()
            print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Starting SSRF fuzzing...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.CYAN}[*] Fuzzing {param}...{Style.RESET_ALL}", end='', flush=True)
        
        payloads = generate_payloads(
            single_url=self.single_url,
            single_ip=self.single_ip,
            wordlist=self.wordlist,
            ip_range=self.ip_range,
            ports=self.ports,
            path=self.path,
            encode=self.encode
        )
        
        results = self._test_payloads(payloads, method, url, headers, body, marker, baseline_size)
        
        if not self.verbose:
            print(" Done!\n")
        
        print_summary(results, baseline_size, self.show_response, 
                     bool(self.single_url), bool(self.single_ip))
    
    def run_from_url(self, url: str, param: str):
        """Run SSRF detection from URL"""
        if self.verbose:
            print(f"{Fore.CYAN}[*] URL: {url}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Parameter: {param}{Style.RESET_ALL}")
            if self.single_url:
                print(f"{Fore.CYAN}[*] Single URL Mode: {self.single_url}{Style.RESET_ALL}")
            if self.single_ip:
                print(f"{Fore.CYAN}[*] Single IP Mode: {self.single_ip}{Style.RESET_ALL}")
            if self.show_response:
                print(f"{Fore.CYAN}[*] Show Response: Enabled{Style.RESET_ALL}")
            print()
        
        found, marker = find_injection_point(url)
        
        if not found:
            print(f"{Fore.RED}[!] Error: Injection marker (SSRF or ***) not found in URL{Style.RESET_ALL}")
            sys.exit(1)
        
        if self.verbose:
            print(f"{Fore.GREEN}[+] Injection marker '{marker}' found{Style.RESET_ALL}\n")
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Establishing baseline response...{Style.RESET_ALL}")
        
        baseline_url = replace_injection_point(url, marker, "")
        baseline_status, baseline_size, baseline_error, _, _ = send_request(
            self.session, "GET", baseline_url, {}, "", self.timeout
        )
        
        if baseline_error:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Baseline request failed: {baseline_error}{Style.RESET_ALL}")
            baseline_size = 0
        else:
            if self.verbose:
                print(f"{Fore.GREEN}[+] Baseline established - Status: {baseline_status}, Size: {baseline_size} bytes{Style.RESET_ALL}")
        
        if self.verbose:
            print()
            print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Starting SSRF fuzzing...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.CYAN}[*] Fuzzing {param}...{Style.RESET_ALL}", end='', flush=True)
        
        payloads = generate_payloads(
            single_url=self.single_url,
            single_ip=self.single_ip,
            wordlist=self.wordlist,
            ip_range=self.ip_range,
            ports=self.ports,
            path=self.path,
            encode=self.encode
        )
        
        results = self._test_payloads_url(payloads, url, marker, baseline_size)
        
        if not self.verbose:
            print(" Done!\n")
        
        print_summary(results, baseline_size, self.show_response,
                     bool(self.single_url), bool(self.single_ip))
    
    def _test_payloads(self, payloads: List[str], method: str, url: str, 
                      headers: Dict, body: str, marker: str, baseline_size: int) -> List[Dict]:
        """Test payloads against request"""
        results = []
        
        for i, payload in enumerate(payloads, 1):
            test_url = replace_injection_point(url, marker, payload)
            test_headers = {k: replace_injection_point(v, marker, payload) for k, v in headers.items()}
            test_body = replace_injection_point(body, marker, payload) if body else ""
            
            if self.verbose:
                print(f"{Fore.YELLOW}[{i}/{len(payloads)}] Testing payload: {payload}{Style.RESET_ALL}")
            elif i % 10 == 0:
                print('.', end='', flush=True)
            
            status, size, error, resp_headers, resp_content = send_request(
                self.session, method, test_url, test_headers, test_body, self.timeout
            )
            
            result = self._process_result(payload, status, size, error, resp_headers, 
                                         resp_content, baseline_size)
            results.append(result)
            
            if self.verbose:
                self._print_result(result)
                print()
        
        return results
    
    def _test_payloads_url(self, payloads: List[str], url: str, marker: str, 
                          baseline_size: int) -> List[Dict]:
        """Test payloads against URL"""
        results = []
        
        for i, payload in enumerate(payloads, 1):
            test_url = replace_injection_point(url, marker, payload)
            
            if self.verbose:
                print(f"{Fore.YELLOW}[{i}/{len(payloads)}] Testing payload: {payload}{Style.RESET_ALL}")
            elif i % 10 == 0:
                print('.', end='', flush=True)
            
            status, size, error, resp_headers, resp_content = send_request(
                self.session, "GET", test_url, {}, "", self.timeout
            )
            
            result = self._process_result(payload, status, size, error, resp_headers,
                                         resp_content, baseline_size)
            results.append(result)
            
            if self.verbose:
                self._print_result(result)
                print()
        
        return results
    
    def _process_result(self, payload: str, status: Optional[int], size: Optional[int],
                       error: Optional[str], resp_headers: Optional[Dict], 
                       resp_content: Optional[bytes], baseline_size: int) -> Dict:
        """Process a single result"""
        if error:
            return {
                'payload': payload,
                'status': None,
                'size': None,
                'error': error,
                'diff_percent': None,
                'confidence': 'NONE',
                'confidence_reason': error,
                'headers': None,
                'content': None
            }
        else:
            if baseline_size > 0:
                diff_percent = abs((size - baseline_size) / baseline_size * 100)
            else:
                diff_percent = 100 if size > 0 else 0
            
            confidence, confidence_reason = calculate_confidence(status, diff_percent)
            
            return {
                'payload': payload,
                'status': status,
                'size': size,
                'error': None,
                'diff_percent': diff_percent,
                'confidence': confidence,
                'confidence_reason': confidence_reason,
                'headers': resp_headers,
                'content': resp_content
            }
    
    def _print_result(self, result: Dict):
        """Print a single result in verbose mode"""
        confidence = result.get('confidence')
        
        if result.get('error'):
            print(f"    {Fore.RED}â””â”€â”€ Error: {result['error']}{Style.RESET_ALL}")
            return
        
        confidence_color = get_confidence_color(confidence)
        status = result['status']
        size = result['size']
        diff_percent = result['diff_percent']
        
        if confidence in ["HIGH", "MEDIUM-HIGH"]:
            print(f"    {Fore.GREEN}â””â”€â”€ Status: {status} | Size: {size} bytes | Diff: {diff_percent:.2f}% | {confidence_color}[{confidence}]{Style.RESET_ALL}")
            if self.show_response:
                display_response_details(status, result['headers'], result['content'], result['payload'])
        elif confidence in ["MEDIUM", "LOW-MEDIUM"]:
            print(f"    {Fore.YELLOW}â””â”€â”€ Status: {status} | Size: {size} bytes | Diff: {diff_percent:.2f}% | {confidence_color}[{confidence}]{Style.RESET_ALL}")
        elif confidence == "LOW":
            print(f"    {Fore.CYAN}â””â”€â”€ Status: {status} | Size: {size} bytes | Diff: {diff_percent:.2f}% | {confidence_color}[{confidence}]{Style.RESET_ALL}")
        elif confidence == "VERY-LOW":
            print(f"    {Style.DIM}â””â”€â”€ Status: {status} | Size: {size} bytes | Diff: {diff_percent:.2f}% | [VERY-LOW]{Style.RESET_ALL}")
        else:
            print(f"    â””â”€â”€ Status: {status} | Size: {size} bytes | Diff: {diff_percent:.2f}%")
