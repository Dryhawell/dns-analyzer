"""IPSECKEY listing tests. No network access. IPsec is never probed."""

from unittest.mock import MagicMock

import dns.resolver

from analyzer.dmarc import evaluate_dmarc
from analyzer.dnssec import evaluate_dnssec
from analyzer.exceptions import DNSTimeoutError
from analyzer.ipseckey import (
    MAX_IPSECKEY,
    algorithm_meaning,
    evaluate_ipseckey,
    gateway_type_meaning,
    record_from_record,
)
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


def _ipseckey(
    value: str = "10 1 2 192.0.2.1 key-length=64",
    name: str = "example.com",
) -> list[DNSRecord]:
    return [DNSRecord("IPSECKEY", name, value, 300)]


def test_gateway_and_algorithm_meanings() -> None:
    assert gateway_type_meaning(0) == "no gateway"
    assert gateway_type_meaning(1) == "IPv4"
    assert gateway_type_meaning(2) == "IPv6"
    assert gateway_type_meaning(3) == "domain name"
    assert gateway_type_meaning(9) == "unknown gateway type"
    assert algorithm_meaning(0) == "no key"
    assert algorithm_meaning(1) == "DSA"
    assert algorithm_meaning(2) == "RSA"
    assert algorithm_meaning(3) == "ECDSA"
    assert algorithm_meaning(4) == "EdDSA"
    assert algorithm_meaning(99) == "unknown algorithm"


def test_ipseckey_not_detected() -> None:
    observation = evaluate_ipseckey("Example.COM", [])
    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "example.com"
    assert observation.ipseckeys == ()
    assert "does not probe IPsec" in observation.note
    assert "key material" in observation.note


def test_ipseckey_found_lists_fields_without_key_bytes() -> None:
    observation = evaluate_ipseckey(
        "example.com",
        [DNSRecord("IPSECKEY", "example.com", "10 1 2 192.0.2.1 key-length=64", 60)],
    )
    assert observation.status == "FOUND"
    item = observation.ipseckeys[0]
    assert item.precedence == 10
    assert item.gateway_type == 1
    assert item.gateway_type_meaning == "IPv4"
    assert item.algorithm == 2
    assert item.algorithm_meaning == "RSA"
    assert item.gateway == "192.0.2.1"
    assert item.key_length == 64
    assert "does not dump" in observation.note


def test_ipseckey_domain_gateway_is_not_followed() -> None:
    observation = evaluate_ipseckey(
        "example.com",
        [
            DNSRecord(
                "IPSECKEY",
                "example.com",
                "5 3 2 Gw.Example.NET. key-length=32",
                60,
            )
        ],
    )
    assert observation.ipseckeys[0].gateway == "gw.example.net"
    assert observation.ipseckeys[0].gateway_type_meaning == "domain name"
    assert "does not resolve" in observation.note


def test_ipseckey_dedupes_sensible_tuple() -> None:
    records = [
        DNSRecord("IPSECKEY", "example.com", "10 3 2 gw.example.net key-length=32", 60),
        DNSRecord("IPSECKEY", "example.com", "10 3 2 Gw.Example.NET. key-length=32", 60),
    ]
    observation = evaluate_ipseckey("example.com", records)
    assert len(observation.ipseckeys) == 1


def test_ipseckey_caps_at_eight() -> None:
    records = [
        DNSRecord(
            "IPSECKEY",
            "example.com",
            f"{index} 1 2 192.0.2.{index} key-length=16",
            60,
        )
        for index in range(MAX_IPSECKEY + 2)
    ]
    observation = evaluate_ipseckey("example.com", records)
    assert len(observation.ipseckeys) == MAX_IPSECKEY
    assert observation.truncated is True


def test_record_from_record_empty_is_none() -> None:
    assert record_from_record(DNSRecord("IPSECKEY", "example.com", "  ", 60)) is None


def test_inspect_ipseckey_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._client = MagicMock()
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()
    observation = resolver.inspect_ipseckey("example.com")
    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "example.com"


def test_inspect_ipseckey_timeout_is_not_detected_with_error() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_ipseckey = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]
    observation = resolver.inspect_ipseckey("Example.COM.")
    assert observation.status == "NOT DETECTED"
    assert observation.error is not None
    resolver.resolve_ipseckey.assert_called_once_with("example.com")


def test_inspect_ipseckey_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_ipseckey = MagicMock(return_value=_ipseckey())  # type: ignore[method-assign]
    observation = resolver.inspect_ipseckey("example.com")
    assert observation.status == "FOUND"
    assert observation.ipseckeys[0].gateway == "192.0.2.1"
    resolver.resolve_ipseckey.assert_called_once_with("example.com")


def test_ipseckey_missing_is_info_and_unscored() -> None:
    observation = evaluate_ipseckey("example.com", [])
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        ipseckey=observation,
    )
    missing = next(item for item in report.findings if item.code == "ipseckey_missing")
    assert missing.severity == "info"
    assert WEIGHTS["ipseckey_missing"] == 0
    assert report.risk.value == 0


def test_ipseckey_timeout_is_info_unreadable() -> None:
    observation = evaluate_ipseckey(
        "example.com", [], error="IPSECKEY query timed out"
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        ipseckey=observation,
    )
    unread = next(item for item in report.findings if item.code == "ipseckey_unreadable")
    assert unread.severity == "info"
    assert not any(item.code == "ipseckey_missing" for item in report.findings)
    assert report.risk.value == 0


def test_analyze_without_ipseckey_stays_unchanged() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
    )
    assert not any(item.code.startswith("ipseckey_") for item in report.findings)
    assert report.risk.value == 0
