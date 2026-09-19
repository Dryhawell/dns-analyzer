"""DNAME listing tests. No network access. Targets are never followed."""

from unittest.mock import MagicMock

import dns.resolver

from analyzer.dmarc import evaluate_dmarc
from analyzer.dname import MAX_DNAME, evaluate_dname, target_from_record
from analyzer.dnssec import evaluate_dnssec
from analyzer.exceptions import DNSTimeoutError
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


def _dname(target: str = "other.example.net", name: str = "example.com") -> list[DNSRecord]:
    return [DNSRecord("DNAME", name, target, 300)]


def test_dname_not_detected() -> None:
    observation = evaluate_dname("Example.COM", [])
    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "example.com"
    assert observation.dnames == ()
    assert "subtree" in observation.note


def test_dname_found_strips_dot() -> None:
    observation = evaluate_dname(
        "example.com",
        [DNSRecord("DNAME", "example.com", "other.example.net.", 60)],
    )
    assert observation.status == "FOUND"
    assert observation.dnames[0].target == "other.example.net"
    assert "does not synthesize" in observation.note


def test_dname_dedupes_targets() -> None:
    records = [
        DNSRecord("DNAME", "example.com", "other.example.net", 60),
        DNSRecord("DNAME", "example.com", "other.example.net.", 60),
    ]
    observation = evaluate_dname("example.com", records)
    assert len(observation.dnames) == 1


def test_dname_caps_at_eight() -> None:
    records = [
        DNSRecord("DNAME", "example.com", f"n{index}.example.net", 60)
        for index in range(MAX_DNAME + 2)
    ]
    observation = evaluate_dname("example.com", records)
    assert len(observation.dnames) == MAX_DNAME
    assert observation.truncated is True


def test_target_from_record_empty_is_none() -> None:
    assert target_from_record(DNSRecord("DNAME", "example.com", "  ", 60)) is None


def test_inspect_dname_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._client = MagicMock()
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()
    observation = resolver.inspect_dname("example.com")
    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "example.com"


def test_inspect_dname_timeout_is_not_detected_with_error() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_dname = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]
    observation = resolver.inspect_dname("Example.COM.")
    assert observation.status == "NOT DETECTED"
    assert observation.error is not None
    resolver.resolve_dname.assert_called_once_with("example.com")


def test_inspect_dname_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_dname = MagicMock(return_value=_dname())  # type: ignore[method-assign]
    observation = resolver.inspect_dname("example.com")
    assert observation.status == "FOUND"
    assert observation.dnames[0].target == "other.example.net"


def test_dname_missing_is_info_and_unscored() -> None:
    observation = evaluate_dname("example.com", [])
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        dname=observation,
    )
    missing = next(item for item in report.findings if item.code == "dname_missing")
    assert missing.severity == "info"
    assert WEIGHTS["dname_missing"] == 0
    assert report.risk.value == 0


def test_dname_timeout_is_info_unreadable() -> None:
    observation = evaluate_dname(
        "example.com", [], error="DNAME query timed out"
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        dname=observation,
    )
    unread = next(item for item in report.findings if item.code == "dname_unreadable")
    assert unread.severity == "info"
    assert not any(item.code == "dname_missing" for item in report.findings)
    assert report.risk.value == 0


def test_analyze_without_dname_stays_unchanged() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
    )
    assert not any(item.code.startswith("dname_") for item in report.findings)
    assert report.risk.value == 0
