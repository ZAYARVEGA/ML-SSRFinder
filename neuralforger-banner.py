#!/usr/bin/env python3
"""
Neural Forger - ASCII Banner Display

Professional ASCII art banner for the Neural Forger framework.
Designed for terminal display with optional colorama support.
"""

from typing import Optional

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False


# Primary banner design
BANNER = r"""
    _   __                     __   ______                          
   / | / /__  __  _________  / /  / ____/___  _________ ____  _____
  /  |/ / _ \/ / / / ___/ _ \/ /  / /_  / __ \/ ___/ __ `/ _ \/ ___/
 / /|  /  __/ /_/ / /  / __ / /  / __/ / /_/ / /  / /_/ /  __/ /    
/_/ |_/\___/\__,_/_/  /_/ /_/_/  /_/    \____/_/   \__, /\___/_/     
                                                   /____/             
"""

TAGLINE = "ML-Powered SSRF Detection Framework"
SEPARATOR = "=" * 64


def print_banner(version: str = "1.0.0", verbosity: int = 1) -> None:
    """
    Display the Neural Forger banner.

    Args:
        version: Current tool version string.
        verbosity: Verbosity level. 0 = quiet (no banner), 1+ = show banner.
    """
    if verbosity == 0:
        return

    if HAS_COLOR:
        print(f"{Fore.CYAN}{BANNER}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}{TAGLINE}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Version {version}{Style.RESET_ALL}")
        print(f"  {Style.DIM}{SEPARATOR}{Style.RESET_ALL}")
        print()
    else:
        print(BANNER)
        print(f"  {TAGLINE}")
        print(f"  Version {version}")
        print(f"  {SEPARATOR}")
        print()


def get_banner_text(version: str = "1.0.0") -> str:
    """
    Return banner as a plain string (for file output / logging).

    Args:
        version: Current tool version string.

    Returns:
        Banner text without color codes.
    """
    lines = [
        BANNER.strip(),
        f"  {TAGLINE}",
        f"  Version {version}",
        f"  {SEPARATOR}",
        "",
    ]
    return "\n".join(lines)
