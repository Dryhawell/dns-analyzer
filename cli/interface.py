"""CLI interface.

Phase 2: accept a domain (or URL), validate/normalize it, print the result.
Full flags (--record, --security, --all, --reverse) arrive in Phase 14.
"""

from __future__ import annotations

import argparse
import sys

from analyzer.validator import DomainValidationError, normalize_domain


def _ensure_utf8_stdout() -> None:
    """Windows consoles often default to a legacy code page."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dns-analyzer",
        description="Analyze DNS records and security signals for a domain.",
        epilog="Phase 2 validates input only. DNS queries are added in later phases.",
    )
    parser.add_argument(
        "domain",
        nargs="?",
        help="Domain name or URL (e.g. example.com or https://example.com/page)",
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    _ensure_utf8_stdout()
    args = build_parser().parse_args(argv)

    if not args.domain:
        print("DNS Analyzer — Phase 2 (domain validation)")
        print()
        print("Usage: python main.py <domain>")
        print("Example: python main.py example.com")
        print("Example: python main.py https://example.com/login")
        return 0

    try:
        domain = normalize_domain(args.domain)
    except DomainValidationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print("DNS ANALYZER")
    print("────────────────────────")
    print()
    print("Input:")
    print(args.domain)
    print()
    print("Normalized domain:")
    print(domain)
    print()
    print("Status: VALID")
    print()
    print("DNS queries are not enabled yet (Phase 3+).")
    return 0
