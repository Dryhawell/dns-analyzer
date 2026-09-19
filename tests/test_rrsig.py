"""RRSIG listing tests. No network access."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from analyzer.dmarc import evaluate_dmarc
from analyzer.dnssec import evaluate_dnssec
from analyzer.models import CoreLookup, DNSRecord
from analyzer.resolver import DNSResolver
from analyzer.risk import WEIGHTS
from analyzer.security import SecurityAnalyzer
from analyzer.spf import inspect_spf
from analyzer.rrsig import RrsigRecord, evaluate_rrsig, parse_rrsig


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


def _rrsig_record(**overrides) -> RrsigRecord:
    values = {
        "type_covered": 1,
        "type_covered_name": "A",
        "algorithm": 13,
        "algorithm_meaning": "ECDSAP256SHA256",
        "labels": 2,
        "original_ttl": 300,
        "inception": 1758240000,
        "expiration": 1760918400,
        "inception_utc": "2025-09-19T00:00:00Z",
        "expiration_utc": "2025-10-20T00:00:00Z",
        "key_tag": 2371,
        "signer": "example.com",
        "signature_length": 64,
    }
    values.update(overrides)
    return RrsigRecord(**values)


def test_evaluate_rrsig_empty_is_not_detected() -> None:
    observation = evaluate_rrsig("example.com", found=False)
    assert observation.status == "NOT DETECTED"
    assert observation.rrsig == ()
    assert "not validate" in observation.note
    assert "broken DNSSEC" in observation.note


def test_evaluate_rrsig_found_strips_and_normalizes() -> None:
    observation = evaluate_rrsig(
        "example.com",
        found=True,
        rrsig=(_rrsig_record(),),
    )
    assert observation.status == "FOUND"
    assert observation.rrsig[0].type_covered_name == "A"
    assert observation.rrsig[0].algorithm == 13
    assert "ECDSAP256SHA256" in observation.rrsig[0].algorithm_meaning
    assert observation.rrsig[0].key_tag == 2371
    assert observation.rrsig[0].inception_utc.endswith("Z")
    assert observation.rrsig[0].expiration_utc.endswith("Z")
    assert observation.rrsig[0].signature_length == 64


def test_evaluate_rrsig_timeout_is_unreadable() -> None:
    observation = evaluate_rrsig(
        "example.com",
        found=False,
        error="RRSIG query timed out",
    )
    assert observation.status == "UNREADABLE"
    assert observation.error == "RRSIG query timed out"


def test_parse_rrsig_truncates_after_eight() -> None:
    rdatas = [
        SimpleNamespace(
            type_covered=1,
            algorithm=13,
            labels=2,
            original_ttl=300,
            inception=1758240000 + index,
            expiration=1760918400,
            key_tag=2371,
            signer="example.com.",
            signature=b"\x00" * 64,
        )
        for index in range(9)
    ]
    parsed, truncated = parse_rrsig(rdatas)
    assert truncated is True
    assert len(parsed) == 8
    assert parsed[0].inception == 1758240000
    assert parsed[-1].inception == 1758240007


def test_parse_rrsig_dedups_and_omits_signature_bytes() -> None:
    rdata = SimpleNamespace(
        type_covered=48,
        algorithm=13,
        labels=2,
        original_ttl=3600,
        inception=1758240000,
        expiration=1760918400,
        key_tag=2371,
        signer="Example.COM.",
        signature=b"\xab" * 64,
    )
    parsed, truncated = parse_rrsig((rdata, rdata))
    assert truncated is False
    assert len(parsed) == 1
    assert parsed[0].type_covered_name == "DNSKEY"
    assert parsed[0].signer == "example.com"
    assert parsed[0].signature_length == 64
    assert "ECDSAP256SHA256" in parsed[0].algorithm_meaning


def test_inspect_rrsig_uses_probe_results() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._dnssec_probe = MagicMock(  # type: ignore[method-assign]
        return_value=(True, False)
    )
    observation = resolver.inspect_rrsig("example.com")
    assert observation.status == "FOUND"
    assert resolver._dnssec_probe.call_count == 1
    assert resolver._dnssec_probe.call_args.args[2] == "RRSIG"


def test_inspect_rrsig_parses_rdata() -> None:
    resolver = DNSResolver(timeout=1.0)
    rdata = SimpleNamespace(
        type_covered=1,
        algorithm=13,
        labels=2,
        original_ttl=300,
        inception=1758240000,
        expiration=1760918400,
        key_tag=2371,
        signer="example.com.",
        signature=b"\x00" * 64,
    )
    resolver._dnssec_probe = MagicMock(  # type: ignore[method-assign]
        return_value=(True, False, (rdata,))
    )
    observation = resolver.inspect_rrsig("Example.COM.")
    assert observation.status == "FOUND"
    assert observation.query_name == "example.com"
    assert observation.rrsig[0].type_covered_name == "A"
    assert observation.rrsig[0].key_tag == 2371
    assert observation.rrsig[0].signature_length == 64
    assert observation.rrsig[0].inception_utc == "2025-09-19T00:00:00Z"


def test_inspect_rrsig_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._dnssec_probe = MagicMock(return_value=(False, False, ()))  # type: ignore[method-assign]
    observation = resolver.inspect_rrsig("example.com")
    assert observation.status == "NOT DETECTED"


def test_inspect_rrsig_timeout_is_unreadable() -> None:
    resolver = DNSResolver(timeout=1.0)

    def probe(_client: object, _name: str, rdtype: str, errors: list[str]):
        errors.append(f"{rdtype} query timed out")
        return False, False, ()

    resolver._dnssec_probe = probe  # type: ignore[method-assign]
    observation = resolver.inspect_rrsig("example.com")
    assert observation.status == "UNREADABLE"
    assert observation.error is not None
    assert "RRSIG" in observation.error


def test_rrsig_missing_is_info_and_unscored() -> None:
    observation = evaluate_rrsig("example.com", found=False)
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        rrsig=observation,
    )
    missing = next(item for item in report.findings if item.code == "rrsig_missing")
    assert missing.severity == "info"
    assert "broken DNSSEC" in missing.description
    assert WEIGHTS["rrsig_missing"] == 0
    assert report.risk.value == 0


def test_rrsig_timeout_is_info_unreadable() -> None:
    observation = evaluate_rrsig(
        "example.com",
        found=False,
        error="RRSIG query timed out",
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        rrsig=observation,
    )
    unread = next(item for item in report.findings if item.code == "rrsig_unreadable")
    assert unread.severity == "info"
    assert not any(item.code == "rrsig_missing" for item in report.findings)
    assert report.risk.value == 0


def test_analyze_without_rrsig_stays_unchanged() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
    )
    assert not any(item.code.startswith("rrsig_") for item in report.findings)
    assert report.risk.value == 0
