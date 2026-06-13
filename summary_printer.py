#!/usr/bin/env python3
"""
Results summary printing functionality
"""

from typing import List, Dict
from colorama import Fore, Style
from response_formatter import format_response_preview


def print_summary(results: List[Dict], baseline_size: int, show_response: bool, single_url: bool, single_ip: bool):
    """
    Print summary of results
    
    Args:
        results: List of result dictionaries
        baseline_size: Baseline response size
        show_response: Whether responses were shown
        single_url: Whether single URL mode was used
        single_ip: Whether single IP mode was used
    """
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] SCAN SUMMARY{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
    
    high_confidence = [r for r in results if r.get('confidence') == 'HIGH']
    medium_high = [r for r in results if r.get('confidence') == 'MEDIUM-HIGH']
    medium = [r for r in results if r.get('confidence') == 'MEDIUM']
    low_medium = [r for r in results if r.get('confidence') == 'LOW-MEDIUM']
    low = [r for r in results if r.get('confidence') == 'LOW']
    very_low = [r for r in results if r.get('confidence') == 'VERY-LOW']
    
    if high_confidence:
        print(f"{Fore.RED}{'â–ˆ'*80}{Style.RESET_ALL}")
        print(f"{Fore.RED}[!] HIGH CONFIDENCE SSRF DETECTED!{Style.RESET_ALL}")
        print(f"{Fore.RED}{'â–ˆ'*80}{Style.RESET_ALL}\n")
        print(f"{Fore.GREEN}[+] These payloads returned Status 200 with significant response differences:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}    â†’ Strong indication of successful SSRF exploitation{Style.RESET_ALL}\n")
        
        for result in high_confidence:
            print(f"  {Fore.RED}âœ“ {result['payload']}{Style.RESET_ALL}")
            print(f"    Status: {result['status']} | Size: {result['size']} bytes | Diff: {result['diff_percent']:.2f}%")
            print(f"    {Style.DIM}Reason: {result['confidence_reason']}{Style.RESET_ALL}")
            
            if show_response and result.get('content'):
                print(f"    {Fore.CYAN}Response Preview:{Style.RESET_ALL}")
                preview = format_response_preview(result['content'], max_length=200)
                for line in preview.split('\n')[:5]:
                    print(f"    {Style.DIM}{line}{Style.RESET_ALL}")
            print()
        
        print(f"{Fore.YELLOW}[!] ACTION: Test these payloads manually to confirm exploitation{Style.RESET_ALL}")
        if not show_response:
            print(f"{Fore.CYAN}[!] TIP: Use --show-response to see HTTP response content{Style.RESET_ALL}")
        print()
    
    if medium_high:
        print(f"{Fore.YELLOW}{'â”€'*80}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] MEDIUM-HIGH CONFIDENCE{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'â”€'*80}{Style.RESET_ALL}\n")
        
        for result in medium_high:
            print(f"  {Fore.YELLOW}â€¢ {result['payload']}{Style.RESET_ALL}")
            print(f"    Status: {result['status']} | Size: {result['size']} bytes | Diff: {result['diff_percent']:.2f}%")
            print()
    
    if medium:
        print(f"{Fore.CYAN}[*] MEDIUM CONFIDENCE: {len(medium)} findings{Style.RESET_ALL}")
    if low + very_low:
        print(f"{Style.DIM}[*] LOW CONFIDENCE: {len(low) + len(very_low)} payloads (likely false positives){Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    
    if high_confidence:
        print(f"{Fore.RED}[âœ“] VERDICT: SSRF vulnerability likely present{Style.RESET_ALL}")
        print(f"{Fore.RED}    â†’ Focus on {len(high_confidence)} high-confidence payload(s){Style.RESET_ALL}")
    elif medium_high or medium:
        print(f"{Fore.YELLOW}[?] VERDICT: Possible SSRF vulnerability{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[âœ—] VERDICT: No high-confidence SSRF indicators detected{Style.RESET_ALL}")
    
    print()
    print(f"{Fore.CYAN}[*] Statistics:{Style.RESET_ALL}")
    print(f"    Total payloads tested: {len(results)}")
    print(f"    Baseline response size: {baseline_size} bytes")
    print(f"    High confidence: {len(high_confidence)}")
    print(f"    Medium-High confidence: {len(medium_high)}")
    print(f"    Medium confidence: {len(medium)}")
    
    if high_confidence and not single_url and not single_ip:
        print()
        print(f"{Fore.CYAN}[*] Follow-up Investigation:{Style.RESET_ALL}")
        print(f"    Use --single-url or --ip with the successful payload to investigate further:")
        for result in high_confidence[:3]:
            # Extract IP from payload for --ip suggestion
            if 'http://' in result['payload']:
                try:
                    host_part = result['payload'].split('://')[1].split('/')[0].split(':')[0]
                    print(f"    {Fore.GREEN}# Using --single-url:{Style.RESET_ALL}")
                    print(f"    python3 ssrfinder.py -r <request.txt> -p <param> --single-url '{result['payload']}' --show-response")
                    print(f"    {Fore.GREEN}# Or using --ip to test more ports:{Style.RESET_ALL}")
                    print(f"    python3 ssrfinder.py -r <request.txt> -p <param> --ip {host_part} --show-response")
                except:
                    print(f"    {Fore.GREEN}python3 ssrfinder.py -r <request.txt> -p <param> --single-url '{result['payload']}' --show-response{Style.RESET_ALL}")
    
    print()
