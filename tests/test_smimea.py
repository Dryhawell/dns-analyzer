"""SMIMEA listing tests. No network access. Certificates are never fetched."""

from unittest.mock import MagicMock

import dns.resolver
import pytest

from analyzer.dmarc import evaluate_dmarc
from analyzer.dnssec import evaluate_dnssec
from analyzer.exceptions import DNSTimeoutError
from analyzer.models import CoreLookup, DNSRecord
from analyzer.resolver import DNSResolver
from analyzer.risk import WEIGHTS
from analyzer.security import SecurityAnalyzer
from analyzer.smimea import (
    HASH_OCTETS,
    MAX_LOCALPARTS,
    MAX_SMIMEA,
    SmimeaLocalpartError,
    evaluate_smimea,
    localpart_hash,
    normalize_localpart,
    normalize_localparts,
    smimea_query_name,
)
from analyzer.spf import inspect_spf


# RFC 8162 §3 example: hugh@example.com
_RFC8162_HUGH_HASH = "c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6"


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


def _smimea_record(
    value: str = "3 1 1 assoc-length=32",
    name: str = f"{_RFC8162_HUGH_HASH}._smimecert.example.com",
) -> DNSRecord:
    parts = value.split()
    return DNSRecord(
        "SMIMEA",
        name,
        value,
        300,
        details=(
            ("Usage", f"{parts[0]} — DANE-EE — domain-issued certificate (PKIX optional)"),
            ("Selector", f"{parts[1]} — SubjectPublicKeyInfo (SPKI)"),
            ("Matching", f"{parts[2]} — SHA-256"),
            ("Association length", parts[3].split("=", 1)[1] if "assoc-length=" in value else "0"),
        ),
    )


def test_rfc8162_hugh_hash() -> None:
    assert localpart_hash("hugh") == _RFC8162_HUGH_HASH
    assert len(localpart_hash("hugh")) == HASH_OCTETS * 2
    assert smimea_query_name("Example.COM", "hugh") == (
        f"{_RFC8162_HUGH_HASH}._smimecert.example.com"
    )


def test_localpart_hash_lowercases_ascii() -> None:
    assert localpart_hash("Hugh") == _RFC8162_HUGH_HASH
    assert localpart_hash("alice@example.com") == localpart_hash("alice")


def test_normalize_localpart_takes_local_part_only() -> None:
    assert normalize_localpart(" Alice@Example.COM ") == "alice"
    assert normalize_localpart("alice") == "alice"


def test_normalize_localpart_rejects_empty() -> None:
    with pytest.raises(SmimeaLocalpartError, match="empty"):
        normalize_localpart("  ")
    with pytest.raises(SmimeaLocalpartError, match="empty"):
        normalize_localpart("@example.com")


def test_normalize_localparts_dedupes_and_caps() -> None:
    assert normalize_localparts(["alice", "Alice", "bob"]) == ("alice", "bob")
    too_many = [f"user{i}" for i in range(MAX_LOCALPARTS + 1)]
    with pytest.raises(SmimeaLocalpartError, match="Too many"):
        normalize_localparts(too_many)


def test_smimea_not_detected() -> None:
    observation = evaluate_smimea(
        f"{_RFC8162_HUGH_HASH}._smimecert.example.com",
        "hugh",
        [],
    )
    assert observation.status == "NOT DETECTED"
    assert observation.associations == ()
    assert observation.local_part == "hugh"
    assert "does not send email" in observation.note
    assert "never guessed" in observation.note


def test_smimea_found_lists_length_not_bytes() -> None:
    observation = evaluate_smimea(
        f"{_RFC8162_HUGH_HASH}._smimecert.example.com",
        "hugh",
        [_smimea_record()],
    )
    assert observation.status == "FOUND"
    item = observation.associations[0]
    assert item.usage == 3
    assert item.selector == 1
    assert item.matching_type == 1
    assert item.association_length == 32
    assert "DANE-EE" in item.usage_meaning
    assert "SPKI" in item.selector_meaning
    assert "SHA-256" in item.matching_meaning
    assert "not certificate validation" in observation.note


def test_smimea_dedupes_usage_selector_matching_length() -> None:
    records = [_smimea_record(), _smimea_record()]
    observation = evaluate_smimea(
        f"{_RFC8162_HUGH_HASH}._smimecert.example.com",
        "hugh",
        records,
    )
    assert len(observation.associations) == 1


def test_smimea_caps_at_eight() -> None:
    records = [
        _smimea_record(f"3 1 1 assoc-length={index + 1}")
        for index in range(MAX_SMIMEA + 2)
    ]
    observation = evaluate_smimea(
        f"{_RFC8162_HUGH_HASH}._smimecert.example.com",
        "hugh",
        records,
    )
    assert len(observation.associations) == MAX_SMIMEA
    assert observation.truncated is True


def test_inspect_smimea_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._client = MagicMock()
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()
    observation = resolver.inspect_smimea("example.com", "alice")
    assert observation.status == "NOT DETECTED"
    assert observation.local_part == "alice"
    assert observation.query_name == smimea_query_name("example.com", "alice")
    assert observation.error is None


def test_inspect_smimea_timeout_is_not_detected_with_error() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_smimea = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]
    observation = resolver.inspect_smimea("Example.COM.", "alice")
    assert observation.status == "NOT DETECTED"
    assert observation.error is not None
    resolver.resolve_smimea.assert_called_once_with(
        smimea_query_name("example.com", "alice")
    )


def test_inspect_smimea_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    qname = smimea_query_name("example.com", "alice")
    resolver.resolve_smimea = MagicMock(  # type: ignore[method-assign]
        return_value=[_smimea_record(name=qname)]
    )
    observation = resolver.inspect_smimea("example.com", "alice")
    assert observation.status == "FOUND"
    assert observation.associations[0].association_length == 32
    resolver.resolve_smimea.assert_called_once_with(qname)


def test_smimea_missing_is_info_and_unscored() -> None:
    observation = evaluate_smimea(
        smimea_query_name("example.com", "alice"),
        "alice",
        [],
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        smimea=(observation,),
    )
    missing = next(item for item in report.findings if item.code == "smimea_missing")
    assert missing.severity == "info"
    assert WEIGHTS["smimea_missing"] == 0
    assert report.risk.value == 0


def test_smimea_timeout_is_info_unreadable() -> None:
    observation = evaluate_smimea(
        smimea_query_name("example.com", "alice"),
        "alice",
        [],
        error="SMIMEA query timed out",
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        smimea=(observation,),
    )
    unread = next(item for item in report.findings if item.code == "smimea_unreadable")
    assert unread.severity == "info"
    assert not any(item.code == "smimea_missing" for item in report.findings)
    assert report.risk.value == 0


def test_analyze_without_smimea_stays_unchanged() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
    )
    assert not any(item.code.startswith("smimea_") for item in report.findings)
    assert report.risk.value == 0
