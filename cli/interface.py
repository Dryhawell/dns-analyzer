"""CLI interface.

Phase 3: validate input, then probe A records through DNSResolver.
Full flags (--record, --security, --all, --reverse) arrive in Phase 14.
"""

from __future__ import annotations

import argparse
import sys

from analyzer.exceptions import DNSQueryError
from analyzer.resolver import DNSResolver
from analyzer.validator import DomainValidationError, normalize_domain

_DEFAULT_TIMEOUT = 5.0


def _ensure_utf8_stdout() -> None:
    """Windows consoles often default to a legacy code page."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dns-analyzer",
        description="Analyze DNS records and security signals for a domain.",
        epilog="Phase 3 probes A records via the system resolver. More record types follow.",
    )
    parser.add_argument(
        "domain",
        nargs="?",
        help="Domain name or URL (e.g. example.com or https://example.com/page)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=_DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"DNS query timeout in seconds (default: {_DEFAULT_TIMEOUT})",
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    _ensure_utf8_stdout()
    args = build_parser().parse_args(argv)

    if not args.domain:
        print("DNS Analyzer — Phase 3 (DNS resolver)")
        print()
        print("Usage: python main.py <domain>")
        print("Example: python main.py example.com")
        print("Example: python main.py example.com --timeout 3")
        return 0

    try:
        domain = normalize_domain(args.domain)
    except DomainValidationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print("DNS ANALYZER")
    print("────────────────────────")
    print()
    print("Target:")
    print(domain)
    print()

    resolver = DNSResolver(timeout=args.timeout)

    try:
        records = resolver.resolve_a(domain)
    except DNSQueryError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print("A RECORDS")
    if not records:
        print("No A record found.")
        return 0

    for record in records:
        print(record.value)
        print(f"TTL: {record.ttl}")
    return 0
