"""CERT listing tests. No network access. PKIX is never validated."""

from unittest.mock import MagicMock

import dns.resolver

from analyzer.cert import (
    MAX_CERT,
    cert_type_meaning,
    evaluate_cert,
    record_from_record,
)
from analyzer.dmarc import evaluate_dmarc
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


def _cert(
    value: str = "1 12345 8 cert-length=64",
    name: str = "example.com",
) -> list[DNSRecord]:
    return [DNSRecord("CERT", name, value, 300)]


def test_cert_type_meanings() -> None:
    assert cert_type_meaning(1) == "PKIX"
    assert cert_type_meaning(2) == "SPKI"
    assert cert_type_meaning(3) == "PGP"
    assert cert_type_meaning(4) == "IPKIX"
    assert cert_type_meaning(5) == "ISPKI"
    assert cert_type_meaning(6) == "IPGP"
    assert cert_type_meaning(7) == "ACPKIX"
    assert cert_type_meaning(8) == "IACPKIX"
    assert cert_type_meaning(253) == "URI"
    assert cert_type_meaning(254) == "OID"
    assert cert_type_meaning(99) == "unknown certificate type"


def test_cert_not_detected() -> None:
    observation = evaluate_cert("Example.COM", [])
    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "example.com"
    assert observation.certs == ()
    assert "does not dump" in observation.note
    assert "does not validate PKIX" in observation.note
    assert "not a replacement for CAA or TLSA" in observation.note


def test_cert_found_lists_fields_without_bytes() -> None:
    observation = evaluate_cert(
        "example.com",
        [DNSRecord("CERT", "example.com", "1 12345 8 cert-length=64", 60)],
    )
    assert observation.status == "FOUND"
    item = observation.certs[0]
    assert item.cert_type == 1
    assert item.cert_type_meaning == "PKIX"
    assert item.key_tag == 12345
    assert item.algorithm == 8
    assert item.algorithm_meaning == "RSA/SHA-256"
    assert item.cert_length == 64
    assert "does not dump" in observation.note


def test_cert_uri_type_is_not_fetched() -> None:
    observation = evaluate_cert(
        "example.com",
        [DNSRecord("CERT", "example.com", "253 1 8 cert-length=32", 60)],
    )
    assert observation.certs[0].cert_type_meaning == "URI"
    assert "does not fetch" in observation.note


def test_cert_dedupes_sensible_tuple() -> None:
    records = [
        DNSRecord("CERT", "example.com", "1 12345 8 cert-length=64", 60),
        DNSRecord("CERT", "example.com", "1 12345 8 cert-length=64", 60),
    ]
    observation = evaluate_cert("example.com", records)
    assert len(observation.certs) == 1


def test_cert_caps_at_eight() -> None:
    records = [
        DNSRecord(
            "CERT",
            "example.com",
            f"1 {index} 8 cert-length={index + 1}",
            60,
        )
        for index in range(MAX_CERT + 2)
    ]
    observation = evaluate_cert("example.com", records)
    assert len(observation.certs) == MAX_CERT
    assert observation.truncated is True


def test_record_from_record_empty_is_none() -> None:
    assert record_from_record(DNSRecord("CERT", "example.com", "  ", 60)) is None


def test_inspect_cert_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._client = MagicMock()
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()
    observation = resolver.inspect_cert("example.com")
    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "example.com"


def test_inspect_cert_timeout_is_not_detected_with_error() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_cert = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]
    observation = resolver.inspect_cert("Example.COM.")
    assert observation.status == "NOT DETECTED"
    assert observation.error is not None
    resolver.resolve_cert.assert_called_once_with("example.com")


def test_inspect_cert_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_cert = MagicMock(return_value=_cert())  # type: ignore[method-assign]
    observation = resolver.inspect_cert("example.com")
    assert observation.status == "FOUND"
    assert observation.certs[0].cert_type_meaning == "PKIX"
    resolver.resolve_cert.assert_called_once_with("example.com")


def test_cert_missing_is_info_and_unscored() -> None:
    observation = evaluate_cert("example.com", [])
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        cert=observation,
    )
    missing = next(item for item in report.findings if item.code == "cert_missing")
    assert missing.severity == "info"
    assert WEIGHTS["cert_missing"] == 0
    assert report.risk.value == 0


def test_cert_timeout_is_info_unreadable() -> None:
    observation = evaluate_cert(
        "example.com", [], error="CERT query timed out"
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        cert=observation,
    )
    unread = next(item for item in report.findings if item.code == "cert_unreadable")
    assert unread.severity == "info"
    assert not any(item.code == "cert_missing" for item in report.findings)
    assert report.risk.value == 0


def test_analyze_without_cert_stays_unchanged() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
    )
    assert not any(item.code.startswith("cert_") for item in report.findings)
    assert report.risk.value == 0
