"""CLI interface.

Phase 6: A, AAAA, CNAME, MX, NS, TXT, SOA, and CAA records.
Full flags (--record, --security, --all, --reverse) arrive in Phase 14.
"""

from __future__ import annotations

import argparse
import sys

from analyzer.exceptions import DNSQueryError
from analyzer.models import CoreLookup, DNSRecord
from analyzer.records import describe_ip_scope
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
        epilog="Phase 6 shows A, AAAA, CNAME, MX, NS, TXT, SOA, and CAA records.",
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


def _print_missing(empty_message: str, section: str, errors: tuple[tuple[str, str], ...]) -> None:
    for label, message in errors:
        if label == section:
            print(f"Error: {message}")
            print()
            return
    print(empty_message)
    print()


def _print_address_section(
    title: str,
    empty_message: str,
    section: str,
    records: tuple[DNSRecord, ...],
    errors: tuple[tuple[str, str], ...],
) -> None:
    print(title)
    if not records:
        _print_missing(empty_message, section, errors)
        return

    for record in records:
        print(record.value)
        print(f"TTL: {record.ttl}")
        scope = describe_ip_scope(record.value)
        if scope:
            print(f"Scope: {scope}")
        print()


def _print_cname_section(
    records: tuple[DNSRecord, ...], errors: tuple[tuple[str, str], ...]
) -> None:
    print("CNAME RECORDS")
    if not records:
        _print_missing("No CNAME record found.", "CNAME", errors)
        return

    for record in records:
        print(f"{record.name} → {record.value}")
        print(f"TTL: {record.ttl}")
        print()


def _print_mx_section(
    records: tuple[DNSRecord, ...], errors: tuple[tuple[str, str], ...]
) -> None:
    print("MX RECORDS")
    if not records:
        _print_missing("No MX record found.", "MX", errors)
        return

    ordered = sorted(
        records,
        key=lambda item: (item.priority is None, item.priority if item.priority is not None else 0, item.value),
    )
    for record in ordered:
        print(record.value)
        if record.priority is not None:
            print(f"Priority: {record.priority}")
        print(f"TTL: {record.ttl}")
        print()


def _print_ns_section(
    records: tuple[DNSRecord, ...], errors: tuple[tuple[str, str], ...]
) -> None:
    print("NS RECORDS")
    if not records:
        _print_missing("No NS record found.", "NS", errors)
        return

    for record in sorted(records, key=lambda item: item.value):
        print(record.value)
        print(f"TTL: {record.ttl}")
        print()


def _print_txt_section(
    records: tuple[DNSRecord, ...], errors: tuple[tuple[str, str], ...]
) -> None:
    print("TXT RECORDS")
    if not records:
        _print_missing("No TXT record found.", "TXT", errors)
        return

    for record in records:
        print(f'"{record.value}"')
        print(f"TTL: {record.ttl}")
        print()


def _print_soa_section(
    records: tuple[DNSRecord, ...], errors: tuple[tuple[str, str], ...]
) -> None:
    print("SOA")
    if not records:
        _print_missing("No SOA record found.", "SOA", errors)
        return

    for record in records:
        for label, value in record.details:
            print(f"{label}: {value}")
        print(f"TTL: {record.ttl}")
        print()


def _print_caa_section(
    records: tuple[DNSRecord, ...], errors: tuple[tuple[str, str], ...]
) -> None:
    print("CAA RECORDS")
    if not records:
        _print_missing("No CAA record found.", "CAA", errors)
        return

    for record in records:
        print(record.value)
        for label, value in record.details:
            print(f"{label}: {value}")
        print(f"TTL: {record.ttl}")
        print()


def _print_lookup(lookup: CoreLookup) -> None:
    errors = lookup.errors
    _print_address_section("A RECORDS", "No A record found.", "A", lookup.a, errors)
    _print_address_section("AAAA RECORDS", "No AAAA record found.", "AAAA", lookup.aaaa, errors)
    _print_cname_section(lookup.cname, errors)
    _print_mx_section(lookup.mx, errors)
    _print_ns_section(lookup.ns, errors)
    _print_txt_section(lookup.txt, errors)
    _print_soa_section(lookup.soa, errors)
    _print_caa_section(lookup.caa, errors)


def run(argv: list[str] | None = None) -> int:
    _ensure_utf8_stdout()
    args = build_parser().parse_args(argv)

    if not args.domain:
        print("DNS Analyzer — Phase 6 (TXT / SOA / CAA)")
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
        lookup = resolver.lookup_core(domain)
    except DNSQueryError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    _print_lookup(lookup)
    return 0
