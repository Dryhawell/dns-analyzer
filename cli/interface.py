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
from analyzer.dkim import DkimObservation, DkimSelectorError, normalize_selectors
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
from analyzer.bimi import BimiObservation
from analyzer.fcrdns import FcrdnsObservation
from analyzer.mx import MxHostObservation
from analyzer.ns import NsHostObservation
from analyzer.cname import CnameTargetObservation
from analyzer.soa import SoaNsObservation
from analyzer.caa import CaaObservation
from analyzer.cds import CdsObservation
from analyzer.nsec import NsecObservation
from analyzer.sshfp import SshfpObservation
from analyzer.tlsa import TlsaObservation
from analyzer.models import CoreLookup, DNSRecord
from analyzer.mtasts import MtaStsObservation
from analyzer.records import describe_ip_scope
from analyzer.resolver import DNSResolver
from analyzer.result import DNSAnalysisResult
from analyzer.reverse import looks_like_ip, parse_ip, ptr_name
from analyzer.risk import RiskScore
from analyzer.security import SecurityAnalyzer, SecurityFinding, SecurityReport
from analyzer.spf import SpfObservation, inspect_spf
from analyzer.srv import SrvObservation, SrvSpecError, normalize_srv_specs
from analyzer.naptr import NaptrObservation
from analyzer.uri import UriObservation
from analyzer.tlsrpt import TlsRptObservation
from analyzer.ttl import describe_cache, format_duration, format_ttl_line, summarize_ttls
from analyzer.validator import DomainValidationError, normalize_domain
from analyzer.version import __version__
from utils.logger import configure_logging, get_logger
from utils.reporter import (
    dumps_csv,
    dumps_html,
    dumps_json,
    format_from_suffix,
    write_report,
)

_DEFAULT_TIMEOUT = 5.0
_MAX_TIMEOUT = 120.0
_RECORD_ORDER = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "HTTPS", "SVCB")
_RECORD_TYPES = frozenset(_RECORD_ORDER)
_SECURITY_QUERY_TYPES = ("A", "AAAA", "CNAME", "TXT", "CAA")
_log = get_logger("cli")

_EPILOG = """
Examples:
  python main.py example.com
  python main.py example.com --record A
  python main.py example.com --record MX --record NS
  python main.py example.com --security
  python main.py example.com --dkim google
  python main.py example.com --srv sip
  python main.py example.com --naptr
  python main.py example.com --uri
  python main.py example.com --format json
  python main.py example.com --format html --output reports/example_com.html
  python main.py example.com --output reports/example_com.json
  python main.py example.com --config config/resolvers.example.json
  python main.py --reverse 8.8.8.8 --format csv
  python main.py --version

Default (no --record / --security) is the same as --all: every record
type plus DNSSEC, SPF, DMARC, MTA-STS, TLS-RPT, BIMI, DANE TLSA, SSHFP, FCrDNS, MX hosts, NS hosts, CNAME targets, SOA/NS, CAA summary, CDS/CDNSKEY, NSEC/NSEC3PARAM, findings, and the local risk score.
--dkim SELECTOR is opt-in; selectors are never guessed.
--srv SERVICE is opt-in; service names (sip, xmpp, …) are never guessed.
--naptr is opt-in; ENUM/SIP applications are never guessed.
--uri is opt-in; the target is not fetched and service prefixes are never guessed.

This is not a vulnerability scanner. Missing DNSSEC, SPF, DMARC, DKIM, CAA,
MTA-STS, TLS-RPT, BIMI, DANE TLSA, SSHFP, SRV, NAPTR, or URI is an observation, not proof of compromise.
Missing PTR / FCrDNS mismatch / MX host issues / NS host issues / CNAME target issues / hidden SOA primary / missing CDS / missing NSEC are also observations, not hijacking.
"""


@dataclass(frozen=True)
class ReportView:
    """What the CLI should print after a forward lookup.

    record_types is None → all core types. An empty frozenset → no record
    sections (security-only). show_security covers DNSSEC/SPF/DMARC/MTA-STS/TLS-RPT/BIMI/DANE TLSA/SSHFP/FCrDNS/MX hosts/NS hosts/CNAME targets/SOA-NS/CAA summary/CDS/CDNSKEY/findings/score.
    """

    record_types: frozenset[str] | None
    show_security: bool


@dataclass(frozen=True)
class ExportPlan:
    """Human stdout vs machine export (JSON/CSV/HTML)."""

    print_human: bool
    file_format: str | None
    path: Path | None


def _ensure_utf8_stdout() -> None:
    """Windows consoles often default to a legacy code page."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")


def _configure_logging() -> None:
    """File log is best-effort. Analysis still runs if the log cannot be created."""
    try:
        configure_logging()
    except OSError as exc:
        print(f"Warning: Could not write log file ({exc}).", file=sys.stderr)


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
        "--version",
        action="version",
        version=f"dns-analyzer {__version__}",
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
            "Show only this record type (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, HTTPS, SVCB). "
            "Repeatable. Other types are not queried. A is always queried first "
            "so NXDOMAIN can abort. PTR is --reverse, not --record PTR. "
            "SRV is --srv, not --record SRV. NAPTR is --naptr, not --record NAPTR. "
            "URI is --uri, not --record URI. "
            "TLSA is DANE at _443._tcp, not --record TLSA. "
            "SSHFP is in the security view, not --record SSHFP. "
            "CDS/CDNSKEY are in the security view, not --record CDS. "
            "NSEC/NSEC3PARAM are in the security view, not --record NSEC."
        ),
    )
    parser.add_argument(
        "--security",
        action="store_true",
        help="Show DNSSEC, SPF, DMARC, MTA-STS, TLS-RPT, BIMI, DANE TLSA, SSHFP, FCrDNS, MX hosts, NS hosts, CNAME targets, SOA/NS, CAA summary, CDS/CDNSKEY, NSEC/NSEC3PARAM, findings, and the local risk score",
    )
    parser.add_argument(
        "--dkim",
        action="append",
        dest="dkim_selectors",
        metavar="SELECTOR",
        help=(
            "Look up this DKIM selector (TXT at SELECTOR._domainkey.<domain>). "
            "Repeatable, max 8. Selectors are never guessed."
        ),
    )
    parser.add_argument(
        "--srv",
        action="append",
        dest="srv_services",
        metavar="SERVICE",
        help=(
            "Look up this SRV service (_SERVICE._tcp.<domain>, or SERVICE/udp). "
            "Repeatable, max 8. Service names are never guessed."
        ),
    )
    parser.add_argument(
        "--naptr",
        action="store_true",
        help=(
            "Look up NAPTR at this domain (order, preference, flags, services, "
            "regexp, replacement). The regexp is not executed and ENUM/SIP "
            "names are never guessed."
        ),
    )
    parser.add_argument(
        "--uri",
        action="store_true",
        help=(
            "Look up URI at this domain (priority, weight, target). "
            "The target is not fetched and service prefixes such as "
            "_http._tcp are never guessed."
        ),
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
        choices=("text", "json", "csv", "html"),
        default="text",
        dest="export_format",
        help="text (default CLI), json, csv, or html. json/csv/html go to stdout unless --output is set",
    )
    parser.add_argument(
        "--output",
        metavar="PATH",
        help="Write JSON, CSV, or HTML to this path. With --format text, suffix must be .json, .csv, or .html",
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
    if value in {"PTR", "SRV", "NAPTR", "URI", "TLSA", "SSHFP", "CDS", "CDNSKEY", "NSEC", "NSEC3", "NSEC3PARAM"}:
        return None
    if value not in _RECORD_TYPES:
        return ""
    return value


def _record_type_error(raw: str) -> str:
    kind = raw.strip().upper()
    if kind == "PTR":
        return "PTR is reverse DNS. Use --reverse <ip>."
    if kind == "SRV":
        return "SRV is not at the apex. Use --srv <service> (for example --srv sip)."
    if kind == "NAPTR":
        return (
            "NAPTR is opt-in. Use --naptr. This tool does not guess ENUM or SIP "
            "applications, and it does not apply the regexp."
        )
    if kind == "URI":
        return (
            "URI is opt-in. Use --uri. This tool does not guess prefixes such as "
            "_http._tcp, and it does not fetch the target."
        )
    if kind == "TLSA":
        return (
            "TLSA is not at the apex. Default / --security query "
            "_443._tcp.<domain> (DANE for HTTPS)."
        )
    if kind == "SSHFP":
        return (
            "SSHFP is queried at this hostname with default / --security. "
            "It is not a --record dump type."
        )
    if kind == "CDS":
        return (
            "CDS is listed with default / --security (RFC 7344 child-to-parent "
            "DS signaling). It is not a --record dump type."
        )
    if kind == "CDNSKEY":
        return (
            "CDNSKEY is listed with default / --security (RFC 7344 child-to-parent "
            "DS signaling). It is not a --record dump type."
        )
    if kind in {"NSEC", "NSEC3", "NSEC3PARAM"}:
        return (
            "NSEC/NSEC3PARAM are listed with default / --security (authenticated "
            "denial at this name). This tool does not walk the NSEC/NSEC3 chain. "
            "It is not a --record dump type."
        )
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
    if args.reverse and (
        has_filter
        or args.security
        or args.all
        or args.dkim_selectors
        or args.srv_services
        or args.naptr
        or args.uri
    ):
        return (
            "Use either a domain (with --record/--security/--all/--dkim/--srv/--naptr/--uri) "
            "or --reverse, not both."
        )

    if args.all or (not has_filter and not args.security):
        return ReportView(record_types=None, show_security=True)
    if has_filter and args.security:
        return ReportView(record_types=frozenset(selected), show_security=True)
    if has_filter:
        return ReportView(record_types=frozenset(selected), show_security=False)
    return ReportView(record_types=frozenset(), show_security=True)


def types_to_query(view: ReportView) -> tuple[str, ...] | None:
    """Which core types to send. None means every CORE type (default / --all).

    --record MX still queries A first (existence). --security skips MX/NS/SOA/HTTPS/SVCB.
    """
    if view.record_types is None:
        return None
    needed: set[str] = {"A"}
    needed.update(view.record_types)
    if view.show_security:
        needed.update(_SECURITY_QUERY_TYPES)
    return tuple(label for label in _RECORD_ORDER if label in needed)


def plan_export(export_format: str, output: str | None) -> ExportPlan | str:
    """Decide human vs JSON/CSV/HTML stdout vs file. Returns an error string on conflict."""
    if export_format == "text":
        if not output:
            return ExportPlan(print_human=True, file_format=None, path=None)
        path = Path(output)
        inferred = format_from_suffix(path)
        if inferred is None:
            return (
                "When using --output in text mode, the path must end in .json, .csv, or .html "
                "(or pass --format json / --format csv / --format html)."
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
    """Write JSON/CSV/HTML to a file or stdout. Return an error message on failure."""
    if export.file_format is None:
        return None
    dumpers = {"json": dumps_json, "csv": dumps_csv, "html": dumps_html}
    try:
        if export.path is not None:
            write_report(export.path, result, export.file_format)
            _log.info("Wrote report %s", export.path)
            print(f"Wrote {export.path}", file=sys.stderr)
            return None
        dump = dumpers.get(export.file_format)
        if dump is None:
            return f"Unsupported export format: {export.file_format}"
        sys.stdout.write(dump(result))
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
        "HTTPS": lookup.https,
        "SVCB": lookup.svcb,
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


def _print_svcb_section(
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
        if record.priority is not None:
            print(f"Priority: {record.priority}")
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
    dkim: tuple[DkimObservation, ...] | None = None,
    srv: tuple[SrvObservation, ...] | None = None,
    mta_sts: MtaStsObservation | None = None,
    tls_rpt: TlsRptObservation | None = None,
    bimi: BimiObservation | None = None,
    tlsa: TlsaObservation | None = None,
    sshfp: SshfpObservation | None = None,
    fcrdns: FcrdnsObservation | None = None,
    mx_hosts: MxHostObservation | None = None,
    ns_hosts: NsHostObservation | None = None,
    cname_targets: CnameTargetObservation | None = None,
    soa_ns: SoaNsObservation | None = None,
    caa: CaaObservation | None = None,
    cds: CdsObservation | None = None,
    nsec: NsecObservation | None = None,
    naptr: NaptrObservation | None = None,
    uri: UriObservation | None = None,
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
        if "HTTPS" in wanted:
            _print_svcb_section(
                "HTTPS RECORDS",
                "No HTTPS record found.",
                "HTTPS",
                lookup.https,
                errors,
            )
        if "SVCB" in wanted:
            _print_svcb_section(
                "SVCB RECORDS",
                "No SVCB record found.",
                "SVCB",
                lookup.svcb,
                errors,
            )
        _print_ttl_summary(_selected_records(lookup, types))
    if dkim:
        for item in dkim:
            _print_dkim(item)
    if srv:
        for item in srv:
            _print_srv(item)
    if naptr is not None:
        _print_naptr(naptr)
    if uri is not None:
        _print_uri(uri)
    if view.show_security:
        if (
            dnssec is None
            or spf is None
            or dmarc is None
            or mta_sts is None
            or tls_rpt is None
            or bimi is None
            or tlsa is None
            or sshfp is None
            or fcrdns is None
            or mx_hosts is None
            or ns_hosts is None
            or cname_targets is None
            or soa_ns is None
            or caa is None
            or cds is None
            or nsec is None
            or security is None
        ):
            raise RuntimeError(
                "Security view is missing DNSSEC/SPF/DMARC/MTA-STS/TLS-RPT/BIMI/TLSA/SSHFP/FCrDNS/MX/NS host/CNAME target/SOA-NS/CAA/CDS/NSEC results."
            )
        _print_dnssec(dnssec)
        _print_cds(cds)
        _print_nsec(nsec)
        _print_spf(spf)
        _print_dmarc(dmarc)
        _print_mta_sts(mta_sts)
        _print_tls_rpt(tls_rpt)
        _print_bimi(bimi)
        _print_tlsa(tlsa)
        _print_sshfp(sshfp)
        _print_fcrdns(fcrdns)
        _print_mx_hosts(mx_hosts)
        _print_ns_hosts(ns_hosts)
        _print_cname_targets(cname_targets)
        _print_soa_ns(soa_ns)
        _print_caa(caa)
        _print_security(security)


def _print_dnssec(observation: DnssecObservation) -> None:
    print("DNSSEC")
    print("────────────────────────")
    print(f"Status: {observation.status}")
    print(f"DNSKEY: {'FOUND' if observation.dnskey_found else 'NOT FOUND'}")
    print(f"DS:     {'FOUND' if observation.ds_found else 'NOT FOUND'}")
    print(f"AD flag: {'SET' if observation.ad_flag else 'NOT SET'} (this resolver)")
    if observation.keys:
        print("Keys:")
        for key in observation.keys:
            tag = f", key tag {key.key_tag}" if key.key_tag is not None else ""
            print(
                f"  {key.flags} {key.protocol} {key.algorithm}  "
                f"({key.role}, {key.algorithm_meaning}{tag})"
            )
        if observation.keys_truncated:
            print("  Note: more than 8 DNSKEY records; extras were not listed.")
    if observation.delegations:
        print("Delegations (DS):")
        for item in observation.delegations:
            print(
                f"  {item.key_tag} {item.algorithm} {item.digest_type}  "
                f"({item.algorithm_meaning}, {item.digest_meaning})"
            )
        if observation.delegations_truncated:
            print("  Note: more than 8 DS records; extras were not listed.")
    if observation.error:
        print(f"Note: {observation.error}")
    print()
    print(observation.note)
    print()


def _print_cds(observation: CdsObservation) -> None:
    print("CDS / CDNSKEY")
    print("────────────────────────")
    print(f"Queried: {observation.query_name}")
    print(f"Status: {observation.status}")
    print(f"CDS:     {'FOUND' if observation.cds_found else 'NOT FOUND'}")
    print(f"CDNSKEY: {'FOUND' if observation.cdnskey_found else 'NOT FOUND'}")
    if observation.status == "NOT DETECTED":
        print("No CDS or CDNSKEY records at this name.")
    if observation.cds:
        print("CDS:")
        for item in observation.cds:
            print(
                f"  {item.key_tag} {item.algorithm} {item.digest_type}  "
                f"({item.algorithm_meaning}, {item.digest_meaning})"
            )
        if observation.cds_truncated:
            print("  Note: more than 8 CDS records; extras were not listed.")
    if observation.cdnskey:
        print("CDNSKEY:")
        for key in observation.cdnskey:
            tag = f", key tag {key.key_tag}" if key.key_tag is not None else ""
            print(
                f"  {key.flags} {key.protocol} {key.algorithm}  "
                f"({key.role}, {key.algorithm_meaning}{tag})"
            )
        if observation.cdnskey_truncated:
            print("  Note: more than 8 CDNSKEY records; extras were not listed.")
    if observation.error:
        print(f"Note: {observation.error}")
    print()
    print(observation.note)
    print()


def _print_nsec(observation: NsecObservation) -> None:
    print("NSEC / NSEC3PARAM")
    print("────────────────────────")
    print(f"Queried: {observation.query_name}")
    print(f"Status: {observation.status}")
    print(f"NSEC3PARAM: {'FOUND' if observation.nsec3param_found else 'NOT FOUND'}")
    print(f"NSEC:       {'FOUND' if observation.nsec_found else 'NOT FOUND'}")
    if observation.status == "NOT DETECTED":
        print("No NSEC or NSEC3PARAM records at this name.")
    if observation.nsec3param:
        print("NSEC3PARAM:")
        for item in observation.nsec3param:
            opt = ", opt-out" if item.opt_out else ""
            print(
                f"  {item.algorithm} {item.flags} {item.iterations}  "
                f"({item.algorithm_meaning}, salt length {item.salt_length}{opt})"
            )
            print(f"  {item.iterations_note}")
        if observation.nsec3param_truncated:
            print("  Note: more than 8 NSEC3PARAM records; extras were not listed.")
    if observation.nsec:
        print("NSEC (this name only; next name is not queried):")
        for item in observation.nsec:
            types = " ".join(item.types) if item.types else "(types not listed)"
            extra = " …" if item.types_truncated else ""
            print(f"  next {item.next_name}  {types}{extra}")
        if observation.nsec_truncated:
            print("  Note: more than 8 NSEC records; extras were not listed.")
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
        if observation.hops:
            print("Includes (one hop; not a full SPF evaluation):")
            for hop in observation.hops:
                label = hop.kind
                if hop.status == "FOUND" and hop.policy:
                    print(f"  {label} {hop.domain}: {hop.policy}")
                    if hop.all_term:
                        print(f"    all: {hop.all_term} ({hop.all_meaning})")
                    if hop.nested_includes:
                        shown = ", ".join(hop.nested_includes)
                        print(f"    nested include: {shown} (not followed)")
                else:
                    extra = f" ({hop.error})" if hop.error else ""
                    print(f"  {label} {hop.domain}: {hop.status}{extra}")
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


def _print_mta_sts(observation: MtaStsObservation) -> None:
    print("MTA-STS")
    print("────────────────────────")
    print(f"Queried: {observation.query_name}")
    print(f"Policy host: {observation.policy_host} (HTTPS file not fetched)")
    print(f"Status: {observation.status}")
    if observation.record:
        print("TXT:")
        print(observation.record)
        if observation.policy_id:
            print(f"id={observation.policy_id}")
        else:
            print("id= (missing)")
        if observation.multiple_records:
            print("Note: multiple v=STSv1 TXT records (receivers may ignore the id).")
    if observation.error:
        print(f"Note: {observation.error}")
    print()
    print(observation.note)
    print()


def _print_tls_rpt(observation: TlsRptObservation) -> None:
    print("TLS-RPT")
    print("────────────────────────")
    print(f"Queried: {observation.query_name}")
    print(f"Status: {observation.status}")
    if observation.record:
        print("TXT:")
        print(observation.record)
        if observation.rua:
            print(f"rua={observation.rua}")
        else:
            print("rua= (missing)")
        if observation.multiple_records:
            print("Note: multiple v=TLSRPTv1 TXT records (senders may ignore rua).")
    if observation.error:
        print(f"Note: {observation.error}")
    print()
    print(observation.note)
    print()


def _print_bimi(observation: BimiObservation) -> None:
    print("BIMI")
    print("────────────────────────")
    print(f"Selector: {observation.selector}")
    print(f"Queried: {observation.query_name}")
    print(f"Status: {observation.status}")
    if observation.record:
        print("TXT:")
        print(observation.record)
        if observation.location:
            print(f"l={observation.location} (URL not fetched)")
        else:
            print("l= (missing)")
        if observation.authority:
            print(f"a={observation.authority} (URL not fetched)")
        if observation.multiple_records:
            print("Note: multiple v=BIMI1 TXT records (receivers may ignore BIMI).")
    if observation.error:
        print(f"Note: {observation.error}")
    print()
    print(observation.note)
    print()


def _print_tlsa(observation: TlsaObservation) -> None:
    print("DANE / TLSA")
    print("────────────────────────")
    print(f"Queried: {observation.query_name}")
    print(f"Port/protocol: {observation.port}/{observation.protocol} (HTTPS)")
    print(f"Status: {observation.status}")
    if observation.associations:
        for item in observation.associations:
            print(
                f"{item.usage} {item.selector} {item.matching_type} {item.association}"
            )
            print(f"  usage: {item.usage_meaning}")
            print(f"  selector: {item.selector_meaning}")
            print(f"  matching: {item.matching_meaning}")
            if item.association_truncated:
                print("  association hex truncated (full certificate not dumped)")
    if observation.error:
        print(f"Note: {observation.error}")
    print()
    print(observation.note)
    print()


def _print_sshfp(observation: SshfpObservation) -> None:
    print("SSHFP")
    print("────────────────────────")
    print(f"Queried: {observation.query_name}")
    print(f"Status: {observation.status}")
    if observation.fingerprints:
        for item in observation.fingerprints:
            print(
                f"{item.algorithm} {item.fingerprint_type} {item.fingerprint}"
            )
            print(f"  algorithm: {item.algorithm_meaning}")
            print(f"  fingerprint type: {item.fingerprint_type_meaning}")
            if item.fingerprint_truncated:
                print("  fingerprint hex truncated")
    if observation.error:
        print(f"Note: {observation.error}")
    print()
    print(observation.note)
    print()


def _print_fcrdns(observation: FcrdnsObservation) -> None:
    print("FCrDNS")
    print("────────────────────────")
    if not observation.checks:
        print("No A/AAAA addresses to check.")
    for item in observation.checks:
        print(f"{item.ip}")
        print(f"  PTR query: {item.ptr_query}")
        print(f"  Status: {item.status}")
        if item.ptr_names:
            print(f"  PTR: {', '.join(item.ptr_names)}")
        if item.forward_ips:
            print(f"  Forward: {', '.join(item.forward_ips)}")
        if item.error:
            print(f"  Note: {item.error}")
    if observation.truncated:
        print("Note: more than 8 addresses; extra A/AAAA were not checked.")
    print()
    print(observation.note)
    print()


def _print_mx_hosts(observation: MxHostObservation) -> None:
    print("MX HOSTS")
    print("────────────────────────")
    print(f"Status: {observation.status}")
    if observation.status == "NOT DETECTED":
        print("No MX records at this name.")
    for item in observation.checks:
        pref = f"  preference {item.preference}" if item.preference is not None else ""
        print(f"{item.host}{pref}")
        print(f"  Status: {item.status}")
        if item.ipv4:
            print(f"  A: {', '.join(item.ipv4)}")
        if item.ipv6:
            print(f"  AAAA: {', '.join(item.ipv6)}")
        if item.error:
            print(f"  Note: {item.error}")
    if observation.truncated:
        print("Note: more than 8 MX hosts; extra targets were not checked.")
    if observation.error:
        print(f"Note: {observation.error}")
    print()
    print(observation.note)
    print()


def _print_ns_hosts(observation: NsHostObservation) -> None:
    print("NS HOSTS")
    print("────────────────────────")
    print(f"Status: {observation.status}")
    if observation.status == "NOT DETECTED":
        print("No NS records at this name.")
    for item in observation.checks:
        scope = "in-bailiwick" if item.in_bailiwick else "out-of-bailiwick"
        print(f"{item.host}  {scope}")
        print(f"  Status: {item.status}")
        if item.ipv4:
            print(f"  A: {', '.join(item.ipv4)}")
        if item.ipv6:
            print(f"  AAAA: {', '.join(item.ipv6)}")
        if item.error:
            print(f"  Note: {item.error}")
    if observation.truncated:
        print("Note: more than 8 NS hosts; extra targets were not checked.")
    if observation.error:
        print(f"Note: {observation.error}")
    print()
    print(observation.note)
    print()


def _print_cname_targets(observation: CnameTargetObservation) -> None:
    print("CNAME TARGETS")
    print("────────────────────────")
    print(f"Status: {observation.status}")
    if observation.status == "NOT DETECTED":
        print("No CNAME records at this name.")
    for item in observation.checks:
        print(item.target)
        print(f"  Status: {item.status}")
        if item.chain:
            print(f"  Chain: {' -> '.join(item.chain)}")
        if item.ipv4:
            print(f"  A: {', '.join(item.ipv4)}")
        if item.ipv6:
            print(f"  AAAA: {', '.join(item.ipv6)}")
        if item.error:
            print(f"  Note: {item.error}")
    if observation.truncated:
        print("Note: more than 8 CNAME targets; extra aliases were not checked.")
    if observation.error:
        print(f"Note: {observation.error}")
    print()
    print(observation.note)
    print()


def _print_soa_ns(observation: SoaNsObservation) -> None:
    print("SOA / NS")
    print("────────────────────────")
    print(f"Status: {observation.status}")
    if observation.status == "NOT DETECTED":
        print("No SOA record at this name.")
    if observation.mname:
        print(f"Primary: {observation.mname}")
    if observation.serial:
        print(f"Serial: {observation.serial}")
    if observation.ns_hosts:
        print(f"NS: {', '.join(observation.ns_hosts)}")
    elif observation.status == "NO NS":
        print("No NS records at this name.")
    if observation.error:
        print(f"Note: {observation.error}")
    print()
    print(observation.note)
    print()


def _print_caa(observation: CaaObservation) -> None:
    print("CAA")
    print("────────────────────────")
    print(f"Status: {observation.status}")
    if observation.status == "NOT DETECTED":
        print("No CAA records at this name.")
    if observation.issue:
        print(f"issue: {', '.join(observation.issue)}")
    if observation.issuewild:
        print(f"issuewild: {', '.join(observation.issuewild)}")
    if observation.iodef:
        print(f"iodef: {', '.join(observation.iodef)}")
    for item in observation.properties:
        critical = ", issuer critical" if item.issuer_critical else ""
        print(
            f'  {item.flags} {item.tag} "{item.value}"  '
            f"({item.tag_meaning}{critical})"
        )
    if observation.truncated:
        print("  Note: more than 8 CAA records; extras were not listed.")
    if observation.error:
        print(f"Note: {observation.error}")
    print()
    print(observation.note)
    print()


def _print_dkim(observation: DkimObservation) -> None:
    print("DKIM")
    print("────────────────────────")
    print(f"Selector: {observation.selector}")
    print(f"Queried: {observation.query_name}")
    print(f"Status: {observation.status}")
    if observation.key_type:
        print(f"Key type: {observation.key_type}")
    if observation.revoked:
        print("Public key: empty (p=) — this selector is revoked")
    elif observation.key_present:
        print(f"Public key: present ({observation.key_chars} characters)")
    if observation.multiple_records:
        print("Note: multiple v=DKIM1 TXT records at this selector.")
    if observation.error:
        print(f"Note: {observation.error}")
    print()
    print(observation.note)
    print()


def _print_srv(observation: SrvObservation) -> None:
    print("SRV")
    print("────────────────────────")
    print(f"Service: {observation.service}/{observation.protocol}")
    print(f"Queried: {observation.query_name}")
    print(f"Status: {observation.status}")
    for record in observation.records:
        print(record.value)
        for label, value in record.details:
            print(f"{label}: {value}")
        print(format_ttl_line(record.ttl))
        print()
    if observation.error:
        print(f"Note: {observation.error}")
        print()
    print(observation.note)
    print()


def _print_naptr(observation: NaptrObservation) -> None:
    print("NAPTR")
    print("────────────────────────")
    print(f"Queried: {observation.query_name}")
    print(f"Status: {observation.status}")
    if observation.status == "NOT DETECTED":
        print("No NAPTR records at this name.")
    for item in observation.rewrites:
        print(
            f'  {item.order} {item.preference} "{item.flags}" "{item.services}" '
            f'"{item.regexp}" {item.replacement}'
        )
        print(f"Order: {item.order} — lower number is tried first")
        print(f"Preference: {item.preference} — among the same order")
        print(f"Flags: {item.flags} — {item.flags_meaning}" if item.flags else f"Flags: {item.flags_meaning}")
        print(f"Services: {item.services}")
        print(f"Regexp: {item.regexp}")
        print(f"Replacement: {item.replacement}")
        print()
    if observation.truncated:
        print("Note: more than 8 NAPTR records; extras were not listed.")
        print()
    if observation.error:
        print(f"Note: {observation.error}")
        print()
    print(observation.note)
    print()


def _print_uri(observation: UriObservation) -> None:
    print("URI")
    print("────────────────────────")
    print(f"Queried: {observation.query_name}")
    print(f"Status: {observation.status}")
    if observation.status == "NOT DETECTED":
        print("No URI records at this name.")
    for item in observation.uris:
        print(f'  {item.priority} {item.weight} "{item.target}"')
        print(f"Priority: {item.priority} — lower number is tried first")
        print(f"Weight: {item.weight} — among the same priority")
        print(f"Target: {item.target}")
        if item.scheme:
            print(f"Scheme: {item.scheme} — {item.scheme_meaning}")
        else:
            print(f"Scheme: {item.scheme_meaning}")
        print()
    if observation.truncated:
        print("Note: more than 8 URI records; extras were not listed.")
        print()
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
    _configure_logging()
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
    print(f"DNS Analyzer {__version__}")
    print()
    print("Usage: python main.py <domain>")
    print("       python main.py <domain> --record A")
    print("       python main.py <domain> --security")
    print("       python main.py <domain> --dkim google")
    print("       python main.py <domain> --srv sip")
    print("       python main.py <domain> --naptr")
    print("       python main.py <domain> --uri")
    print("       python main.py <domain> --format json")
    print("       python main.py <domain> --format html --output reports/example.html")
    print("       python main.py <domain> --output reports/example.json")
    print("       python main.py <domain> --config config/resolvers.example.json")
    print("       python main.py --reverse <ip>")
    print("       python main.py --version")
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
            _configure_logging()
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
        _configure_logging()
        _log.error("Invalid CLI options")
        print(f"Error: {view}", file=sys.stderr)
        return 1

    export = plan_export(args.export_format, args.output)
    if isinstance(export, str):
        _configure_logging()
        _log.error("Invalid CLI options")
        print(f"Error: {export}", file=sys.stderr)
        return 1

    settings = settings_from_args(args)
    if isinstance(settings, str):
        _configure_logging()
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
            or args.dkim_selectors
            or args.srv_services
            or args.naptr
            or args.uri
        )
        if extra or args.export_format != "text":
            print("Error: Provide a domain, or use --reverse <ip>.", file=sys.stderr)
            return 1
        _print_usage()
        return 0

    if looks_like_ip(args.domain):
        _configure_logging()
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
        _configure_logging()
        _log.error("Invalid domain")
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    try:
        selectors = (
            normalize_selectors(args.dkim_selectors) if args.dkim_selectors else ()
        )
    except DkimSelectorError as exc:
        _configure_logging()
        _log.error("Invalid DKIM selector")
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    try:
        srv_specs = normalize_srv_specs(args.srv_services) if args.srv_services else ()
    except SrvSpecError as exc:
        _configure_logging()
        _log.error("Invalid SRV service")
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    _configure_logging()
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
    dkim_observations = None
    srv_observations = None
    mta_sts = None
    tls_rpt = None
    bimi = None
    tlsa = None
    sshfp = None
    fcrdns = None
    mx_hosts = None
    ns_hosts = None
    cname_targets = None
    soa_ns = None
    caa = None
    cds = None
    nsec = None
    naptr_observation = None
    uri_observation = None
    try:
        extra_optin = (1 if args.naptr else 0) + (1 if args.uri else 0)
        if view.show_security:
            workers = 8 + len(selectors) + len(srv_specs) + extra_optin
            with ThreadPoolExecutor(max_workers=min(8, max(8, workers))) as pool:
                fut_dnssec = pool.submit(resolver.inspect_dnssec, domain)
                fut_dmarc = pool.submit(resolver.inspect_dmarc, domain)
                fut_mtasts = pool.submit(resolver.inspect_mta_sts, domain)
                fut_tlsrpt = pool.submit(resolver.inspect_tls_rpt, domain)
                fut_bimi = pool.submit(resolver.inspect_bimi, domain)
                fut_tlsa = pool.submit(resolver.inspect_tlsa, domain)
                fut_sshfp = pool.submit(resolver.inspect_sshfp, domain)
                fut_fcrdns = pool.submit(resolver.inspect_fcrdns, lookup)
                fut_mx_hosts = pool.submit(resolver.inspect_mx_hosts, domain)
                fut_ns_hosts = pool.submit(resolver.inspect_ns_hosts, domain)
                fut_cname_targets = pool.submit(resolver.inspect_cname_targets, lookup)
                fut_soa_ns = pool.submit(resolver.inspect_soa_ns, domain)
                fut_caa = pool.submit(resolver.inspect_caa, domain)
                fut_cds = pool.submit(resolver.inspect_cds, domain)
                fut_nsec = pool.submit(resolver.inspect_nsec, domain)
                fut_dkim = [
                    pool.submit(resolver.inspect_dkim, domain, sel)
                    for sel in selectors
                ]
                fut_srv = [
                    pool.submit(resolver.inspect_srv, domain, spec)
                    for spec in srv_specs
                ]
                fut_naptr = (
                    pool.submit(resolver.inspect_naptr, domain) if args.naptr else None
                )
                fut_uri = (
                    pool.submit(resolver.inspect_uri, domain) if args.uri else None
                )
                dnssec = fut_dnssec.result()
                dmarc = fut_dmarc.result()
                mta_sts = fut_mtasts.result()
                tls_rpt = fut_tlsrpt.result()
                bimi = fut_bimi.result()
                tlsa = fut_tlsa.result()
                sshfp = fut_sshfp.result()
                fcrdns = fut_fcrdns.result()
                mx_hosts = fut_mx_hosts.result()
                ns_hosts = fut_ns_hosts.result()
                cname_targets = fut_cname_targets.result()
                soa_ns = fut_soa_ns.result()
                caa = fut_caa.result()
                cds = fut_cds.result()
                nsec = fut_nsec.result()
                if selectors:
                    dkim_observations = tuple(item.result() for item in fut_dkim)
                if srv_specs:
                    srv_observations = tuple(item.result() for item in fut_srv)
                if fut_naptr is not None:
                    naptr_observation = fut_naptr.result()
                if fut_uri is not None:
                    uri_observation = fut_uri.result()
            spf = inspect_spf(lookup.txt, lookup.errors)
            spf = resolver.expand_spf(spf)
            security = SecurityAnalyzer().analyze(
                lookup,
                dnssec,
                spf,
                dmarc,
                dkim_observations or (),
                srv_observations or (),
                mta_sts,
                tls_rpt,
                bimi,
                tlsa,
                sshfp,
                fcrdns,
                mx_hosts,
                ns_hosts,
                cname_targets,
                soa_ns,
                caa,
                naptr=naptr_observation,
                uri=uri_observation,
                cds=cds,
                nsec=nsec,
            )
        elif selectors or srv_specs or args.naptr or args.uri:
            extra = len(selectors) + len(srv_specs) + extra_optin
            if extra >= 2:
                with ThreadPoolExecutor(max_workers=min(8, extra)) as pool:
                    fut_dkim = [
                        pool.submit(resolver.inspect_dkim, domain, sel)
                        for sel in selectors
                    ]
                    fut_srv = [
                        pool.submit(resolver.inspect_srv, domain, spec)
                        for spec in srv_specs
                    ]
                    fut_naptr = (
                        pool.submit(resolver.inspect_naptr, domain) if args.naptr else None
                    )
                    fut_uri = (
                        pool.submit(resolver.inspect_uri, domain) if args.uri else None
                    )
                    if selectors:
                        dkim_observations = tuple(item.result() for item in fut_dkim)
                    if srv_specs:
                        srv_observations = tuple(item.result() for item in fut_srv)
                    if fut_naptr is not None:
                        naptr_observation = fut_naptr.result()
                    if fut_uri is not None:
                        uri_observation = fut_uri.result()
            else:
                if selectors:
                    dkim_observations = tuple(
                        resolver.inspect_dkim(domain, sel) for sel in selectors
                    )
                if srv_specs:
                    srv_observations = tuple(
                        resolver.inspect_srv(domain, spec) for spec in srv_specs
                    )
                if args.naptr:
                    naptr_observation = resolver.inspect_naptr(domain)
                if args.uri:
                    uri_observation = resolver.inspect_uri(domain)
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
        mta_sts=mta_sts,
        tls_rpt=tls_rpt,
        bimi=bimi,
        tlsa=tlsa,
        sshfp=sshfp,
        fcrdns=fcrdns,
        mx_hosts=mx_hosts,
        ns_hosts=ns_hosts,
        cname_targets=cname_targets,
        soa_ns=soa_ns,
        caa=caa,
        cds=cds,
        nsec=nsec,
        dkim=dkim_observations,
        srv=srv_observations,
        naptr=naptr_observation,
        uri=uri_observation,
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
        _print_lookup(
            lookup,
            dnssec,
            spf,
            dmarc,
            security,
            view,
            dkim_observations,
            srv_observations,
            mta_sts,
            tls_rpt,
            bimi,
            tlsa,
            sshfp,
            fcrdns,
            mx_hosts,
            ns_hosts,
            cname_targets,
            soa_ns,
            caa,
            cds,
            nsec,
            naptr_observation,
            uri_observation,
        )
        if comparison is not None:
            _print_comparison(comparison)

    error = _emit_export(result, export)
    if error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0
