"""CSYNC listing tests. No network access."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from analyzer.csync import CsyncRecord, evaluate_csync, parse_csync
from analyzer.dmarc import evaluate_dmarc
from analyzer.dnssec import evaluate_dnssec
from analyzer.models import CoreLookup, DNSRecord
from analyzer.resolver import DNSResolver
from analyzer.risk import WEIGHTS
from analyzer.security import SecurityAnalyzer
from analyzer.spf import inspect_spf


def _clean_lookup() -> CoreLookup:
    return CoreLookup(
        a=(DNSRecord("A", "example.com", "93.184.216.34", 300),),
        aaaa=(),
        cname=(),
        mx=(),
        ns=(),
        txt=(DNSRecord("TXT", "example.com", "v=spf1 -all", 300),),
        soa=(),
        caa=(DNSRecord("CAA", "example.com", '0 issue "letsencrypt.org"', 3600),),
    )


def _csync_record(**overrides) -> CsyncRecord:
    values = {
        "serial": 2026091501,
        "flags": 3,
        "immediate": True,
        "soa_minimum": True,
        "types": ("NS", "A", "AAAA"),
        "types_truncated": False,
    }
    values.update(overrides)
    return CsyncRecord(**values)


def test_evaluate_csync_found_lists_types() -> None:
    observation = evaluate_csync(
        "example.com",
        found=True,
        csync=(_csync_record(),),
    )
    assert observation.status == "FOUND"
    assert observation.csync[0].serial == 2026091501
    assert observation.csync[0].immediate is True
    assert "NS" in observation.csync[0].types
    assert "parent registry" in observation.note
    assert "security score" in observation.note


def test_evaluate_csync_not_detected() -> None:
    observation = evaluate_csync("example.com", found=False)
    assert observation.status == "NOT DETECTED"
    assert observation.csync == ()


def test_evaluate_csync_timeout_is_unreadable() -> None:
    observation = evaluate_csync(
        "example.com",
        found=False,
        error="CSYNC query timed out",
    )
    assert observation.status == "UNREADABLE"
    assert observation.error == "CSYNC query timed out"


def test_parse_csync_truncates_after_eight() -> None:
    rdatas = [
        SimpleNamespace(serial=index, flags=1, types=("NS",))
        for index in range(9)
    ]
    parsed, truncated = parse_csync(rdatas)
    assert truncated is True
    assert len(parsed) == 8
    assert parsed[0].serial == 0
    assert parsed[-1].serial == 7


def test_parse_csync_flags_and_types() -> None:
    rdata = SimpleNamespace(serial=1, flags=3, types=("NS", "A", "AAAA"))
    parsed, truncated = parse_csync((rdata,))
    assert truncated is False
    assert parsed[0].immediate is True
    assert parsed[0].soa_minimum is True
    assert parsed[0].types == ("NS", "A", "AAAA")


def test_inspect_csync_uses_probe_results() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._dnssec_probe = MagicMock(  # type: ignore[method-assign]
        return_value=(True, False)
    )
    observation = resolver.inspect_csync("example.com")
    assert observation.status == "FOUND"
    assert resolver._dnssec_probe.call_count == 1
    assert resolver._dnssec_probe.call_args.args[2] == "CSYNC"


def test_inspect_csync_parses_rdata() -> None:
    resolver = DNSResolver(timeout=1.0)
    rdata = SimpleNamespace(serial=2026091501, flags=1, types=("NS", "A"))
    resolver._dnssec_probe = MagicMock(  # type: ignore[method-assign]
        return_value=(True, False, (rdata,))
    )
    observation = resolver.inspect_csync("Example.COM.")
    assert observation.status == "FOUND"
    assert observation.query_name == "example.com"
    assert observation.csync[0].serial == 2026091501
    assert observation.csync[0].immediate is True
    assert observation.csync[0].soa_minimum is False
    assert "NS" in observation.csync[0].types


def test_inspect_csync_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._dnssec_probe = MagicMock(return_value=(False, False, ()))  # type: ignore[method-assign]
    observation = resolver.inspect_csync("example.com")
    assert observation.status == "NOT DETECTED"


def test_inspect_csync_timeout_is_unreadable() -> None:
    resolver = DNSResolver(timeout=1.0)

    def probe(_client: object, _name: str, rdtype: str, errors: list[str]):
        errors.append(f"{rdtype} query timed out")
        return False, False, ()

    resolver._dnssec_probe = probe  # type: ignore[method-assign]
    observation = resolver.inspect_csync("example.com")
    assert observation.status == "UNREADABLE"
    assert observation.error is not None
    assert "CSYNC" in observation.error


def test_csync_missing_is_info_and_unscored() -> None:
    observation = evaluate_csync("example.com", found=False)
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        csync=observation,
    )
    missing = next(item for item in report.findings if item.code == "csync_missing")
    assert missing.severity == "info"
    assert "broken DNS" in missing.description
    assert WEIGHTS["csync_missing"] == 0
    assert report.risk.value == 0


def test_csync_timeout_is_info_unreadable() -> None:
    observation = evaluate_csync(
        "example.com",
        found=False,
        error="CSYNC query timed out",
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        csync=observation,
    )
    unread = next(item for item in report.findings if item.code == "csync_unreadable")
    assert unread.severity == "info"
    assert not any(item.code == "csync_missing" for item in report.findings)
    assert report.risk.value == 0


def test_analyze_without_csync_stays_unchanged() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
    )
    assert not any(item.code.startswith("csync_") for item in report.findings)
    assert report.risk.value == 0
