"""CLI interface.

Phase 9: forward records, reverse DNS, TTL summary, DNSSEC detection.
"""

from __future__ import annotations

import argparse
import sys

from analyzer.dnssec import DnssecObservation
from analyzer.exceptions import DNSQueryError, InvalidIPError
from analyzer.models import CoreLookup, DNSRecord
from analyzer.records import describe_ip_scope
from analyzer.resolver import DNSResolver
from analyzer.reverse import looks_like_ip, parse_ip, ptr_name
from analyzer.ttl import describe_cache, format_duration, format_ttl_line, summarize_ttls
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
        epilog="Forward lookup: python main.py example.com | Reverse: python main.py --reverse 8.8.8.8",
    )
    parser.add_argument(
        "domain",
        nargs="?",
        help="Domain name or URL (e.g. example.com or https://example.com/page)",
    )
    parser.add_argument(
        "--reverse",
        metavar="IP",
        help="Reverse DNS (PTR) lookup for an IPv4 or IPv6 address",
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
        print(format_ttl_line(record.ttl))
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
        print(format_ttl_line(record.ttl))
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
        print(format_ttl_line(record.ttl))
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
        print(format_ttl_line(record.ttl))
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
        print(format_ttl_line(record.ttl))
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
        print(format_ttl_line(record.ttl))
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
        print(format_ttl_line(record.ttl))
        print()


def _print_ttl_summary(records: tuple[DNSRecord, ...]) -> None:
    print("TTL SUMMARY")
    print("────────────────────────")
    observation = summarize_ttls(records)
    if observation is None:
        print("No TTL values to compare.")
        print()
        print("TTL is a cache lifetime, not a security score.")
        print("Values are remaining TTL at this resolver, not always the zone original.")
        print()
        return

    short_types = ", ".join(observation.shortest_types)
    long_types = ", ".join(observation.longest_types)
    print(f"Records: {observation.record_count}")
    print(
        f"Shortest: {format_duration(observation.shortest)} ({short_types}) — "
        f"{describe_cache(observation.shortest)}"
    )
    print(
        f"Longest:  {format_duration(observation.longest)} ({long_types}) — "
        f"{describe_cache(observation.longest)}"
    )
    print("TTL is a cache lifetime, not a security score.")
    print("Values are remaining TTL at this resolver, not always the zone original.")
    print()


def _print_lookup(lookup: CoreLookup, dnssec: DnssecObservation) -> None:
    errors = lookup.errors
    _print_address_section("A RECORDS", "No A record found.", "A", lookup.a, errors)
    _print_address_section("AAAA RECORDS", "No AAAA record found.", "AAAA", lookup.aaaa, errors)
    _print_cname_section(lookup.cname, errors)
    _print_mx_section(lookup.mx, errors)
    _print_ns_section(lookup.ns, errors)
    _print_txt_section(lookup.txt, errors)
    _print_soa_section(lookup.soa, errors)
    _print_caa_section(lookup.caa, errors)
    _print_ttl_summary(lookup.all_records())
    _print_dnssec(dnssec)


def _print_dnssec(observation: DnssecObservation) -> None:
    print("DNSSEC")
    print("────────────────────────")
    print(f"Status: {observation.status}")
    print(f"DNSKEY: {'FOUND' if observation.dnskey_found else 'NOT FOUND'}")
    print(f"DS:     {'FOUND' if observation.ds_found else 'NOT FOUND'}")
    print(f"AD flag: {'SET' if observation.ad_flag else 'NOT SET'} (this resolver)")
    if observation.error:
        print(f"Note: {observation.error}")
    print()
    print(observation.note)
    print()


def _print_reverse(ip: str, ptr_qname: str, records: list[DNSRecord]) -> None:
    print("REVERSE DNS")
    print("────────────────────────")
    print()
    print(ip)
    print()
    if not records:
        print("No PTR record found.")
        print()
        print(f"Queried: {ptr_qname}")
        return

    for record in records:
        print(f"→ {record.value}")
        print(format_ttl_line(record.ttl))
        print()
    print(f"Queried: {ptr_qname}")
    print()
    _print_ttl_summary(tuple(records))


def _run_reverse(ip_raw: str, timeout: float) -> int:
    try:
        addr = parse_ip(ip_raw)
    except InvalidIPError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    ip_text = str(addr)
    qname = ptr_name(ip_text)
    resolver = DNSResolver(timeout=timeout)
    try:
        records = resolver.resolve_reverse(ip_text)
    except DNSQueryError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    _print_reverse(ip_text, qname, records)
    return 0


def _print_usage() -> None:
    print("DNS Analyzer — Phase 9 (DNSSEC)")
    print()
    print("Usage: python main.py <domain>")
    print("       python main.py --reverse <ip>")
    print("Example: python main.py example.com")
    print("Example: python main.py --reverse 8.8.8.8")


def run(argv: list[str] | None = None) -> int:
    _ensure_utf8_stdout()
    args = build_parser().parse_args(argv)

    if args.reverse and args.domain:
        print("Error: Use either a domain or --reverse, not both.", file=sys.stderr)
        return 1

    if args.reverse:
        return _run_reverse(args.reverse, args.timeout)

    if not args.domain:
        _print_usage()
        return 0

    if looks_like_ip(args.domain):
        print(
            "Error: That looks like an IP address. Use --reverse "
            f"{args.domain.strip()}",
            file=sys.stderr,
        )
        return 1

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

    dnssec = resolver.inspect_dnssec(domain)
    _print_lookup(lookup, dnssec)
    return 0
