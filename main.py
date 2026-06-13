#!/usr/bin/env python3
"""
SSRFinder v0.2.5 Beta
Advanced SSRF Detection Tool with Single URL Testing and Response Viewing
Author: Security Research Team
"""

import sys
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Import modules
from banner import print_banner
from cli_parser import create_argument_parser
from ssrfinder_class import SSRFinder


def main():
    """Main function"""
    print_banner()
    
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Validate arguments
    if not args.request and not args.url:
        print(f"{Fore.RED}[!] Error: Either -r/--request or -u/--url must be specified{Style.RESET_ALL}")
        parser.print_help()
        sys.exit(1)
    
    if args.request and args.url:
        print(f"{Fore.RED}[!] Error: Cannot use both -r/--request and -u/--url simultaneously{Style.RESET_ALL}")
        sys.exit(1)
    
    # Check for conflicting options
    exclusive_options = [args.wordlist, args.ip_range, args.single_url, args.ip]
    if sum(bool(x) for x in exclusive_options) > 1:
        print(f"{Fore.RED}[!] Error: Only one of --wordlist, --ip-range, --ip, or --single-url can be used at a time{Style.RESET_ALL}")
        sys.exit(1)
    
    verbose = not args.quiet
    finder = SSRFinder(
        timeout=args.timeout, 
        wordlist=args.wordlist, 
        ip_range=args.ip_range,
        ports=args.ports,
        verbose=verbose,
        path=args.path,
        encode=args.encode,
        show_response=args.show_response,
        single_url=args.single_url,
        single_ip=args.ip
    )
    
    if args.request:
        finder.run_from_request_file(args.request, args.param)
    else:
        finder.run_from_url(args.url, args.param)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Unexpected error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
