"""CLI interface.

Human output and flags. Resolver comparison is optional (--config / --nameserver).
"""

from __future__ import annotations

import argparse
import math
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from analyzer.compare import (
    ResolverComparison,
    compare_snapshots,
    empty_snapshot,
    snapshot_from_lookup,
    types_for_comparison,
)
from analyzer.config import (
    ResolverSettings,
    load_resolver_file,
    nameserver_arg,
    os_default_settings,
    select_resolvers,
    settings_from_nameservers,
)
from analyzer.dmarc import DmarcObservation
from analyzer.dnssec import DnssecObservation
from analyzer.exceptions import (
    DNSNetworkError,
    DNSQueryError,
    DNSTimeoutError,
    DomainNotFoundError,
    InvalidIPError,
    NoNameserversError,
    ResolverConfigError,
)
from analyzer.models import CoreLookup, DNSRecord
from analyzer.records import describe_ip_scope
from analyzer.resolver import DNSResolver
from analyzer.result import DNSAnalysisResult
from analyzer.reverse import looks_like_ip, parse_ip, ptr_name
from analyzer.risk import RiskScore
from analyzer.security import SecurityAnalyzer, SecurityFinding, SecurityReport
from analyzer.spf import SpfObservation, inspect_spf
from analyzer.ttl import describe_cache, format_duration, format_ttl_line, summarize_ttls
from analyzer.validator import DomainValidationError, normalize_domain
from utils.logger import configure_logging, get_logger
from utils.reporter import (
    dumps_csv,
    dumps_json,
    format_from_suffix,
    write_report,
)

_DEFAULT_TIMEOUT = 5.0
_MAX_TIMEOUT = 120.0
_RECORD_ORDER = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")
_RECORD_TYPES = frozenset(_RECORD_ORDER)
_SECURITY_QUERY_TYPES = ("A", "AAAA", "CNAME", "TXT", "CAA")
_log = get_logger("cli")

_EPILOG = """
Examples:
  python main.py example.com
  python main.py example.com --record A
  python main.py example.com --record MX --record NS
  python main.py example.com --security
  python main.py example.com --format json
  python main.py example.com --output reports/example_com.json
  python main.py example.com --config config/resolvers.example.json
  python main.py --reverse 8.8.8.8 --format csv

Default (no --record / --security) is the same as --all: every record
type plus DNSSEC, SPF, DMARC, findings, and the local risk score.

This is not a vulnerability scanner. Missing DNSSEC, SPF, DMARC, or CAA
is an observation, not proof of compromise.
"""


@dataclass(frozen=True)
class ReportView:
    """What the CLI should print after a forward lookup.

    record_types is None → all core types. An empty frozenset → no record
    sections (security-only). show_security covers DNSSEC/SPF/DMARC/findings/score.
    """

    record_types: frozenset[str] | None
    show_security: bool


@dataclass(frozen=True)
class ExportPlan:
    """Human stdout vs machine export (JSON/CSV)."""

    print_human: bool
    file_format: str | None
    path: Path | None


def _ensure_utf8_stdout() -> None:
    """Windows consoles often default to a legacy code page."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dns-analyzer",
        description=(
            "Analyze DNS records and security signals for a domain. "
            "Findings are configuration observations, not CVE assignments."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "domain",
        nargs="?",
        help="Domain name or URL (e.g. example.com or https://example.com/page)",
    )
    parser.add_argument(
        "--record",
        action="append",
        dest="records",
        metavar="TYPE",
        help=(
            "Show only this record type (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA). "
            "Repeatable. Other types are not queried. A is always queried first "
            "so NXDOMAIN can abort. PTR is --reverse, not --record PTR."
        ),
    )
    parser.add_argument(
        "--security",
        action="store_true",
        help="Show DNSSEC, SPF, DMARC, findings, and the local risk score",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Show every record type plus security analysis (default)",
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
        help=f"DNS query timeout in seconds (default: {_DEFAULT_TIMEOUT}, max: {_MAX_TIMEOUT:.0f})",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "csv"),
        default="text",
        dest="export_format",
        help="text (default CLI), json, or csv. json/csv go to stdout unless --output is set",
    )
    parser.add_argument(
        "--output",
        metavar="PATH",
        help="Write JSON or CSV to this path. With --format text, suffix must be .json or .csv",
    )
    parser.add_argument(
        "--config",
        dest="config_path",
        metavar="PATH",
        help=(
            "JSON file listing named recursive resolvers (see config/resolvers.example.json). "
            "Two or more entries compare A/AAAA. IPs are not hard-coded in the program."
        ),
    )
    parser.add_argument(
        "--resolver",
        action="append",
        dest="resolver_names",
        metavar="NAME",
        help="Use this named resolver from --config. Repeatable. Order is the compare order",
    )
    parser.add_argument(
        "--nameserver",
        action="append",
        dest="nameservers",
        metavar="IP",
        help=(
            "Query this recursive resolver IP instead of the OS list. Repeatable. "
            "Do not combine with --config."
        ),
    )
    return parser


def _normalize_record_type(raw: str) -> str | None:
    value = raw.strip().upper()
    if value == "PTR":
        return None
    if value not in _RECORD_TYPES:
        return ""
    return value


def _record_type_error(raw: str) -> str:
    if raw.strip().upper() == "PTR":
        return "PTR is reverse DNS. Use --reverse <ip>."
    allowed = ", ".join(_RECORD_ORDER)
    return f"Unknown record type {raw!r}. Use one of: {allowed}."


def resolve_report_view(args: argparse.Namespace) -> ReportView | str:
    """Build the print plan, or return an error string."""
    selected: list[str] = []
    for raw in args.records or []:
        normalized = _normalize_record_type(raw)
        if normalized is None or normalized == "":
            return _record_type_error(raw)
        if normalized not in selected:
            selected.append(normalized)

    has_filter = bool(selected)
    if args.all and (has_filter or args.security):
        return "Do not combine --all with --record or --security. --all is the full report."
    if args.reverse and (has_filter or args.security or args.all):
        return "Use either a domain (with --record/--security/--all) or --reverse, not both."

    if args.all or (not has_filter and not args.security):
        return ReportView(record_types=None, show_security=True)
    if has_filter and args.security:
        return ReportView(record_types=frozenset(selected), show_security=True)
    if has_filter:
        return ReportView(record_types=frozenset(selected), show_security=False)
    return ReportView(record_types=frozenset(), show_security=True)


def types_to_query(view: ReportView) -> tuple[str, ...] | None:
    """Which core types to send. None means every CORE type (default / --all).

    --record MX still queries A first (existence). --security skips MX/NS/SOA.
    """
    if view.record_types is None:
        return None
    needed: set[str] = {"A"}
    needed.update(view.record_types)
    if view.show_security:
        needed.update(_SECURITY_QUERY_TYPES)
    return tuple(label for label in _RECORD_ORDER if label in needed)


def plan_export(export_format: str, output: str | None) -> ExportPlan | str:
    """Decide human vs JSON/CSV stdout vs file. Returns an error string on conflict."""
    if export_format == "text":
        if not output:
            return ExportPlan(print_human=True, file_format=None, path=None)
        path = Path(output)
        inferred = format_from_suffix(path)
        if inferred is None:
            return (
                "When using --output in text mode, the path must end in .json or .csv "
                "(or pass --format json / --format csv)."
            )
        return ExportPlan(print_human=True, file_format=inferred, path=path)

    if output:
        path = Path(output)
        inferred = format_from_suffix(path)
        if inferred is not None and inferred != export_format:
            return f"--format {export_format} does not match output suffix {path.suffix}."
        return ExportPlan(print_human=False, file_format=export_format, path=path)
    return ExportPlan(print_human=False, file_format=export_format, path=None)


def settings_from_args(args: argparse.Namespace) -> ResolverSettings | str:
    """OS resolver, --nameserver list, or --config file. Returns an error string."""
    has_config = bool(args.config_path)
    has_ips = bool(args.nameservers)
    has_names = bool(args.resolver_names)
    if has_config and has_ips:
        return "Use either --config or --nameserver, not both."
    if has_names and not has_config:
        return "Use --resolver with --config."
    try:
        if has_ips:
            return settings_from_nameservers(args.nameservers)
        if has_config:
            loaded = load_resolver_file(Path(args.config_path))
            return select_resolvers(loaded, args.resolver_names)
        return os_default_settings()
    except ResolverConfigError as exc:
        return str(exc)


def _timeout_error(value: float) -> str | None:
    if not math.isfinite(value) or value <= 0:
        return "Timeout must be a positive number of seconds."
    if value > _MAX_TIMEOUT:
        return f"Timeout cannot exceed {_MAX_TIMEOUT:.0f} seconds."
    return None


def _print_dns_failure(exc: DNSQueryError, target: str) -> None:
    """User-facing DNS errors — no traceback, no library class names."""
    if isinstance(exc, DomainNotFoundError):
        print(f"Error: Domain does not exist ({target}).", file=sys.stderr)
    elif isinstance(exc, DNSTimeoutError):
        print(
            "Error: DNS query timed out. Try a larger --timeout or check the network.",
            file=sys.stderr,
        )
    elif isinstance(exc, NoNameserversError):
        print(
            "Error: No nameservers available (SERVFAIL or empty resolver list).",
            file=sys.stderr,
        )
    elif isinstance(exc, DNSNetworkError):
        print("Error: Network error while querying DNS.", file=sys.stderr)
    else:
        print(f"Error: {exc}", file=sys.stderr)


def _view_record_types(view: ReportView) -> tuple[str, ...] | None:
    if view.record_types is None:
        return None
    return tuple(label for label in _RECORD_ORDER if label in view.record_types)


def _emit_export(result: DNSAnalysisResult, export: ExportPlan) -> str | None:
    """Write JSON/CSV to a file or stdout. Return an error message on failure."""
    if export.file_format is None:
        return None
    try:
        if export.path is not None:
            write_report(export.path, result, export.file_format)
            _log.info("Wrote report %s", export.path)
            print(f"Wrote {export.path}", file=sys.stderr)
            return None
        text = dumps_json(result) if export.file_format == "json" else dumps_csv(result)
        sys.stdout.write(text)
        _log.info("Wrote %s report to stdout", export.file_format)
        return None
    except OSError as exc:
        _log.error("Could not write report")
        return f"Could not write report: {exc}"


def _selected_records(lookup: CoreLookup, types: frozenset[str] | None) -> tuple[DNSRecord, ...]:
    if types is None:
        return lookup.all_records()
    buckets = {
        "A": lookup.a,
        "AAAA": lookup.aaaa,
        "CNAME": lookup.cname,
        "MX": lookup.mx,
        "NS": lookup.ns,
        "TXT": lookup.txt,
        "SOA": lookup.soa,
        "CAA": lookup.caa,
    }
    records: list[DNSRecord] = []
    for label in _RECORD_ORDER:
        if label in types:
            records.extend(buckets[label])
    return tuple(records)


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


def _print_lookup(
    lookup: CoreLookup,
    dnssec: DnssecObservation | None,
    spf: SpfObservation | None,
    dmarc: DmarcObservation | None,
    security: SecurityReport | None,
    view: ReportView,
) -> None:
    errors = lookup.errors
    types = view.record_types
    show_records = types is None or bool(types)
    if show_records:
        wanted = _RECORD_TYPES if types is None else types
        if "A" in wanted:
            _print_address_section("A RECORDS", "No A record found.", "A", lookup.a, errors)
        if "AAAA" in wanted:
            _print_address_section("AAAA RECORDS", "No AAAA record found.", "AAAA", lookup.aaaa, errors)
        if "CNAME" in wanted:
            _print_cname_section(lookup.cname, errors)
        if "MX" in wanted:
            _print_mx_section(lookup.mx, errors)
        if "NS" in wanted:
            _print_ns_section(lookup.ns, errors)
        if "TXT" in wanted:
            _print_txt_section(lookup.txt, errors)
        if "SOA" in wanted:
            _print_soa_section(lookup.soa, errors)
        if "CAA" in wanted:
            _print_caa_section(lookup.caa, errors)
        _print_ttl_summary(_selected_records(lookup, types))
    if view.show_security:
        assert dnssec is not None and spf is not None and dmarc is not None and security is not None
        _print_dnssec(dnssec)
        _print_spf(spf)
        _print_dmarc(dmarc)
        _print_security(security)


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


def _print_spf(observation: SpfObservation) -> None:
    print("SPF")
    print("────────────────────────")
    print(f"Status: {observation.status}")
    if observation.policies:
        print("Policy:")
        print(observation.policies[0])
        if observation.all_term:
            print(f"all: {observation.all_term} ({observation.all_meaning})")
        if observation.multiple_records:
            print("Note: multiple v=spf1 TXT records (RFC 7208 expects one).")
    if observation.error:
        print(f"Note: {observation.error}")
    print()
    print(observation.note)
    print()


def _print_dmarc(observation: DmarcObservation) -> None:
    print("DMARC")
    print("────────────────────────")
    print(f"Queried: {observation.query_name}")
    print(f"Status: {observation.status}")
    if observation.record:
        print("Policy record:")
        print(observation.record)
        if observation.policy:
            meaning = observation.policy_meaning or ""
            extra = f" ({meaning})" if meaning else ""
            print(f"p={observation.policy}{extra}")
        if observation.subdomain_policy:
            print(f"sp={observation.subdomain_policy}")
        if observation.pct:
            print(f"pct={observation.pct}")
        if observation.rua:
            print(f"rua={observation.rua}")
        if observation.multiple_records:
            print("Note: multiple v=DMARC1 TXT records (receivers may ignore DMARC).")
    if observation.error:
        print(f"Note: {observation.error}")
    print()
    print(observation.note)
    print()


def _print_security(report: SecurityReport) -> None:
    print("SECURITY ANALYSIS")
    print("────────────────────────")
    if not report.findings:
        print("No findings from this pass.")
        print()
    else:
        print(f"Findings: {len(report.findings)}")
        print()
        for finding in report.findings:
            _print_finding(finding)
    print(report.disclaimer)
    print()
    _print_risk(report.risk)


def _print_finding(finding: SecurityFinding) -> None:
    print(f"[{finding.severity.upper()}] {finding.title}")
    print(finding.description)
    print(f"Recommendation: {finding.recommendation}")
    print()


def _print_risk(risk: RiskScore) -> None:
    print("RISK SCORE")
    print("────────────────────────")
    print(f"Score: {risk.value}/100")
    print(f"Band:  {risk.band}")
    print()
    if risk.contributions:
        print("Contributions:")
        for item in risk.contributions:
            print(f"  +{item.points}  {item.label}")
        if risk.capped:
            print(f"  (raw total {risk.raw_total} capped at 100)")
        print()
    else:
        print("No scored findings.")
        print()
    print(risk.note)
    print()


def _print_comparison(comparison: ResolverComparison) -> None:
    print("RESOLVER COMPARISON")
    print("────────────────────────")
    print(f"Primary: {comparison.primary}")
    extras = [item.name for item in comparison.snapshots[1:]]
    if extras:
        print(f"Compared: {', '.join(extras)}")
    print(f"Status: {comparison.status}")
    if comparison.inconsistent_types:
        print("Potential DNS inconsistency: " + ", ".join(comparison.inconsistent_types))
    print()
    labels: list[str] = []
    for item in comparison.snapshots:
        for label in item.answers:
            if label not in labels:
                labels.append(label)
    for label in labels:
        print(label)
        for item in comparison.snapshots:
            if item.error:
                shown = f"(error: {item.error})"
            else:
                values = item.answers.get(label, ())
                shown = ", ".join(values) if values else "(none)"
            print(f"  {item.name}: {shown}")
        print()
    print(comparison.note)
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


def _compare_with_extras(
    domain: str,
    primary_lookup: CoreLookup,
    settings: ResolverSettings,
    timeout: float,
    compare_types: tuple[str, ...],
) -> ResolverComparison | None:
    """Query extra resolvers for A/AAAA only. Failures become snapshots, not aborts."""
    if not settings.extras or not compare_types:
        return None
    snapshots = [
        snapshot_from_lookup(
            settings.primary.name,
            primary_lookup,
            compare_types,
            settings.primary.nameservers,
        )
    ]
    for extra in settings.extras:
        if settings.delay_seconds:
            time.sleep(settings.delay_seconds)
        _log.info("Querying extra resolver name=%s", extra.name)
        client = DNSResolver(timeout=timeout, nameservers=nameserver_arg(extra))
        try:
            lookup = client.lookup_core(domain, types=compare_types)
        except DNSQueryError as exc:
            _log.warning("Extra resolver %s failed", extra.name)
            snapshots.append(
                empty_snapshot(extra.name, compare_types, extra.nameservers, str(exc))
            )
            continue
        snapshots.append(
            snapshot_from_lookup(extra.name, lookup, compare_types, extra.nameservers)
        )
    return compare_snapshots(snapshots, compare_types)


def _run_reverse(
    ip_raw: str,
    timeout: float,
    export: ExportPlan,
    nameservers: list[str] | None = None,
) -> int:
    configure_logging()
    try:
        addr = parse_ip(ip_raw)
    except InvalidIPError as exc:
        _log.error("Invalid IP for reverse lookup")
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    ip_text = str(addr)
    qname = ptr_name(ip_text)
    _log.info("DNS analysis started target=%s mode=reverse", ip_text)
    started = time.perf_counter()
    scan_time = datetime.now(timezone.utc).isoformat()
    resolver = DNSResolver(timeout=timeout, nameservers=nameservers)
    try:
        records = resolver.resolve_reverse(ip_text)
    except DNSQueryError as exc:
        _log.error("DNS analysis failed target=%s reason=%s", ip_text, exc)
        _print_dns_failure(exc, ip_text)
        return 1

    duration_ms = max(0, int((time.perf_counter() - started) * 1000))
    _log.info(
        "DNS analysis finished target=%s duration_ms=%s records=%s",
        ip_text,
        duration_ms,
        len(records),
    )
    result = DNSAnalysisResult(
        target=ip_text,
        mode="reverse",
        scan_time=scan_time,
        duration_ms=duration_ms,
        records=tuple(records),
        ptr_query=qname,
        view_record_types=("PTR",),
        view_security=False,
    )
    if export.print_human:
        _print_reverse(ip_text, qname, records)
    error = _emit_export(result, export)
    if error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


def _print_usage() -> None:
    print("DNS Analyzer")
    print()
    print("Usage: python main.py <domain>")
    print("       python main.py <domain> --record A")
    print("       python main.py <domain> --security")
    print("       python main.py <domain> --format json")
    print("       python main.py <domain> --output reports/example.json")
    print("       python main.py <domain> --config config/resolvers.example.json")
    print("       python main.py --reverse <ip>")
    print("Example: python main.py example.com")
    print("Example: python main.py --reverse 8.8.8.8")
    print()
    print("See python main.py --help for all options.")


def run(argv: list[str] | None = None) -> int:
    """CLI entry. DNS and network failures return 1 without a traceback."""
    try:
        return _run(argv)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 1
    except Exception:
        try:
            configure_logging()
            _log.exception("Unexpected error")
        except OSError:
            pass
        print(
            "Error: Unexpected failure. Details were written to the log file.",
            file=sys.stderr,
        )
        return 1


def _run(argv: list[str] | None = None) -> int:
    _ensure_utf8_stdout()
    args = build_parser().parse_args(argv)
    timeout_problem = _timeout_error(args.timeout)
    if timeout_problem:
        print(f"Error: {timeout_problem}", file=sys.stderr)
        return 1

    view = resolve_report_view(args)
    if isinstance(view, str):
        configure_logging()
        _log.error("Invalid CLI options")
        print(f"Error: {view}", file=sys.stderr)
        return 1

    export = plan_export(args.export_format, args.output)
    if isinstance(export, str):
        configure_logging()
        _log.error("Invalid CLI options")
        print(f"Error: {export}", file=sys.stderr)
        return 1

    settings = settings_from_args(args)
    if isinstance(settings, str):
        configure_logging()
        _log.error("Invalid CLI options")
        print(f"Error: {settings}", file=sys.stderr)
        return 1

    if args.reverse and args.domain:
        print("Error: Use either a domain or --reverse, not both.", file=sys.stderr)
        return 1

    if args.reverse:
        if settings.extras:
            _log.info("Reverse lookup uses only the primary resolver")
        return _run_reverse(
            args.reverse,
            args.timeout,
            export,
            nameserver_arg(settings.primary),
        )

    if not args.domain:
        extra = (
            args.records
            or args.security
            or args.all
            or args.output
            or args.config_path
            or args.nameservers
            or args.resolver_names
        )
        if extra or args.export_format != "text":
            print("Error: Provide a domain, or use --reverse <ip>.", file=sys.stderr)
            return 1
        _print_usage()
        return 0

    if looks_like_ip(args.domain):
        configure_logging()
        _log.error("Positional argument looks like an IP address")
        print(
            "Error: That looks like an IP address. Use --reverse "
            f"{args.domain.strip()}",
            file=sys.stderr,
        )
        return 1

    try:
        domain = normalize_domain(args.domain)
    except DomainValidationError as exc:
        configure_logging()
        _log.error("Invalid domain")
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    configure_logging()
    _log.info(
        "DNS analysis started target=%s mode=forward resolver=%s",
        domain,
        settings.primary.name,
    )
    started = time.perf_counter()
    scan_time = datetime.now(timezone.utc).isoformat()
    resolver = DNSResolver(
        timeout=args.timeout,
        nameservers=nameserver_arg(settings.primary),
    )
    needed = types_to_query(view)

    try:
        lookup = resolver.lookup_core(domain, types=needed)
    except DNSQueryError as exc:
        _log.error("DNS analysis failed target=%s reason=%s", domain, exc)
        _print_dns_failure(exc, domain)
        return 1

    dnssec = None
    spf = None
    dmarc = None
    security = None
    try:
        if view.show_security:
            with ThreadPoolExecutor(max_workers=2) as pool:
                fut_dnssec = pool.submit(resolver.inspect_dnssec, domain)
                fut_dmarc = pool.submit(resolver.inspect_dmarc, domain)
                dnssec = fut_dnssec.result()
                dmarc = fut_dmarc.result()
            spf = inspect_spf(lookup.txt, lookup.errors)
            security = SecurityAnalyzer().analyze(lookup, dnssec, spf, dmarc)
    except DNSQueryError as exc:
        _log.error("DNS analysis failed target=%s reason=%s", domain, exc)
        _print_dns_failure(exc, domain)
        return 1

    comparison = _compare_with_extras(
        domain,
        lookup,
        settings,
        args.timeout,
        types_for_comparison(needed),
    )

    duration_ms = max(0, int((time.perf_counter() - started) * 1000))
    _log.info(
        "DNS analysis finished target=%s duration_ms=%s records=%s",
        domain,
        duration_ms,
        len(lookup.all_records()),
    )
    collected = lookup.all_records()
    if needed is not None:
        collected = tuple(record for record in collected if record.record_type in needed)
    result = DNSAnalysisResult(
        target=domain,
        mode="forward",
        scan_time=scan_time,
        duration_ms=duration_ms,
        records=collected,
        errors=lookup.errors,
        dnssec=dnssec,
        spf=spf,
        dmarc=dmarc,
        security=security,
        view_record_types=_view_record_types(view),
        view_security=view.show_security,
        comparison=comparison,
    )

    if export.print_human:
        print("DNS ANALYZER")
        print("────────────────────────")
        print()
        print("Target:")
        print(domain)
        print()
        if args.config_path or args.nameservers:
            print("Resolver:")
            print(settings.primary.name)
            print()
        _print_lookup(lookup, dnssec, spf, dmarc, security, view)
        if comparison is not None:
            _print_comparison(comparison)

    error = _emit_export(result, export)
    if error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0
