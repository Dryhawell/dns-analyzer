"""OPENPGPKEY listing tests. No network access. Keys are never dumped."""

from unittest.mock import MagicMock

import dns.resolver
import pytest

from analyzer.dmarc import evaluate_dmarc
from analyzer.dnssec import evaluate_dnssec
from analyzer.exceptions import DNSTimeoutError
from analyzer.models import CoreLookup, DNSRecord
from analyzer.openpgpkey import (
    HASH_OCTETS,
    MAX_LOCALPARTS,
    MAX_OPENPGPKEY,
    OpenpgpkeyLocalpartError,
    evaluate_openpgpkey,
    localpart_hash,
    normalize_localpart,
    normalize_localparts,
    openpgpkey_query_name,
)
from analyzer.resolver import DNSResolver
from analyzer.risk import WEIGHTS
from analyzer.security import SecurityAnalyzer
from analyzer.smimea import localpart_hash as smimea_localpart_hash
from analyzer.spf import inspect_spf


# RFC 7929 example: hugh@example.com (same 28-octet SHA-256 as RFC 8162)
_RFC7929_HUGH_HASH = "c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6"


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


def _openpgpkey_record(
    value: str = "key-length=64",
    name: str = f"{_RFC7929_HUGH_HASH}._openpgpkey.example.com",
) -> DNSRecord:
    length = value.split("=", 1)[1] if "key-length=" in value else "0"
    return DNSRecord(
        "OPENPGPKEY",
        name,
        value,
        300,
        details=(("Key length", length),),
    )


def test_rfc7929_hugh_hash_matches_smimea_helper() -> None:
    assert localpart_hash("hugh") == _RFC7929_HUGH_HASH
    assert localpart_hash("hugh") == smimea_localpart_hash("hugh")
    assert len(localpart_hash("hugh")) == HASH_OCTETS * 2
    assert openpgpkey_query_name("Example.COM", "hugh") == (
        f"{_RFC7929_HUGH_HASH}._openpgpkey.example.com"
    )


def test_localpart_hash_lowercases_ascii() -> None:
    assert localpart_hash("Hugh") == _RFC7929_HUGH_HASH
    assert localpart_hash("alice@example.com") == localpart_hash("alice")


def test_normalize_localpart_takes_local_part_only() -> None:
    assert normalize_localpart(" Alice@Example.COM ") == "alice"
    assert normalize_localpart("alice") == "alice"


def test_normalize_localpart_rejects_empty() -> None:
    with pytest.raises(OpenpgpkeyLocalpartError, match="empty"):
        normalize_localpart("  ")
    with pytest.raises(OpenpgpkeyLocalpartError, match="empty"):
        normalize_localpart("@example.com")


def test_normalize_localparts_dedupes_and_caps() -> None:
    assert normalize_localparts(["alice", "Alice", "bob"]) == ("alice", "bob")
    too_many = [f"user{i}" for i in range(MAX_LOCALPARTS + 1)]
    with pytest.raises(OpenpgpkeyLocalpartError, match="Too many"):
        normalize_localparts(too_many)


def test_openpgpkey_not_detected() -> None:
    observation = evaluate_openpgpkey(
        f"{_RFC7929_HUGH_HASH}._openpgpkey.example.com",
        "hugh",
        [],
    )
    assert observation.status == "NOT DETECTED"
    assert observation.keys == ()
    assert observation.local_part == "hugh"
    assert "does not dump key bytes" in observation.note
    assert "never guessed" in observation.note
    assert "not SMIMEA" in observation.note
    assert "keyserver" in observation.note


def test_openpgpkey_found_lists_length_not_bytes() -> None:
    observation = evaluate_openpgpkey(
        f"{_RFC7929_HUGH_HASH}._openpgpkey.example.com",
        "hugh",
        [_openpgpkey_record()],
    )
    assert observation.status == "FOUND"
    item = observation.keys[0]
    assert item.key_length == 64
    assert "not proof that this mailbox uses working OpenPGP" in observation.note


def test_openpgpkey_dedupes_by_key_length() -> None:
    records = [_openpgpkey_record(), _openpgpkey_record()]
    observation = evaluate_openpgpkey(
        f"{_RFC7929_HUGH_HASH}._openpgpkey.example.com",
        "hugh",
        records,
    )
    assert len(observation.keys) == 1


def test_openpgpkey_caps_at_eight() -> None:
    records = [
        _openpgpkey_record(f"key-length={index + 1}")
        for index in range(MAX_OPENPGPKEY + 2)
    ]
    observation = evaluate_openpgpkey(
        f"{_RFC7929_HUGH_HASH}._openpgpkey.example.com",
        "hugh",
        records,
    )
    assert len(observation.keys) == MAX_OPENPGPKEY
    assert observation.truncated is True


def test_inspect_openpgpkey_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._client = MagicMock()
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()
    observation = resolver.inspect_openpgpkey("example.com", "alice")
    assert observation.status == "NOT DETECTED"
    assert observation.local_part == "alice"
    assert observation.query_name == openpgpkey_query_name("example.com", "alice")
    assert observation.error is None


def test_inspect_openpgpkey_timeout_is_not_detected_with_error() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_openpgpkey = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]
    observation = resolver.inspect_openpgpkey("Example.COM.", "alice")
    assert observation.status == "NOT DETECTED"
    assert observation.error is not None
    resolver.resolve_openpgpkey.assert_called_once_with(
        openpgpkey_query_name("example.com", "alice")
    )


def test_inspect_openpgpkey_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    qname = openpgpkey_query_name("example.com", "alice")
    resolver.resolve_openpgpkey = MagicMock(  # type: ignore[method-assign]
        return_value=[_openpgpkey_record(name=qname)]
    )
    observation = resolver.inspect_openpgpkey("example.com", "alice")
    assert observation.status == "FOUND"
    assert observation.keys[0].key_length == 64
    resolver.resolve_openpgpkey.assert_called_once_with(qname)


def test_openpgpkey_missing_is_info_and_unscored() -> None:
    observation = evaluate_openpgpkey(
        openpgpkey_query_name("example.com", "alice"),
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
        openpgpkey=(observation,),
    )
    missing = next(item for item in report.findings if item.code == "openpgpkey_missing")
    assert missing.severity == "info"
    assert WEIGHTS["openpgpkey_missing"] == 0
    assert report.risk.value == 0


def test_openpgpkey_timeout_is_info_unreadable() -> None:
    observation = evaluate_openpgpkey(
        openpgpkey_query_name("example.com", "alice"),
        "alice",
        [],
        error="OPENPGPKEY query timed out",
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        openpgpkey=(observation,),
    )
    unread = next(item for item in report.findings if item.code == "openpgpkey_unreadable")
    assert unread.severity == "info"
    assert not any(item.code == "openpgpkey_missing" for item in report.findings)
    assert report.risk.value == 0


def test_analyze_without_openpgpkey_stays_unchanged() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
    )
    assert not any(item.code.startswith("openpgpkey_") for item in report.findings)
    assert report.risk.value == 0


def test_never_invents_local_parts() -> None:
    assert normalize_localparts(["alice"]) == ("alice",)
    assert normalize_localparts([]) == ()
