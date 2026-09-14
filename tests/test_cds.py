"""CDS / CDNSKEY listing tests. No network access."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from analyzer.cds import (
    CdnskeyRecord,
    CdsRecord,
    evaluate_cds,
    parse_cdnskey,
    parse_cds,
)
from analyzer.resolver import DNSResolver
from analyzer.security import SecurityAnalyzer
from analyzer.dmarc import evaluate_dmarc
from analyzer.dnssec import evaluate_dnssec
from analyzer.models import CoreLookup, DNSRecord
from analyzer.risk import WEIGHTS
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


def _cds_record(**overrides) -> CdsRecord:
    values = {
        "key_tag": 2371,
        "algorithm": 13,
        "algorithm_meaning": "ECDSAP256SHA256",
        "digest_type": 2,
        "digest_meaning": "SHA-256",
    }
    values.update(overrides)
    return CdsRecord(**values)


def _cdnskey_record(**overrides) -> CdnskeyRecord:
    values = {
        "flags": 257,
        "protocol": 3,
        "algorithm": 13,
        "algorithm_meaning": "ECDSAP256SHA256",
        "role": "KSK",
        "zone_key": True,
        "secure_entry_point": True,
        "key_tag": 2371,
    }
    values.update(overrides)
    return CdnskeyRecord(**values)


def test_evaluate_cds_found_lists_algorithm_and_digest() -> None:
    observation = evaluate_cds(
        "example.com",
        cds_found=True,
        cdnskey_found=True,
        cds=(_cds_record(),),
        cdnskey=(_cdnskey_record(),),
    )
    assert observation.status == "FOUND"
    assert observation.cds[0].algorithm == 13
    assert observation.cds[0].digest_type == 2
    assert observation.cds[0].digest_meaning == "SHA-256"
    assert observation.cdnskey[0].algorithm == 13
    assert observation.cdnskey[0].role == "KSK"
    assert "parent registry" in observation.note
    assert "broken DNSSEC" in observation.note


def test_evaluate_cds_not_detected() -> None:
    observation = evaluate_cds(
        "example.com", cds_found=False, cdnskey_found=False
    )
    assert observation.status == "NOT DETECTED"
    assert observation.cds == ()
    assert observation.cdnskey == ()


def test_evaluate_cds_timeout_is_unreadable() -> None:
    observation = evaluate_cds(
        "example.com",
        cds_found=False,
        cdnskey_found=False,
        error="CDS query timed out",
    )
    assert observation.status == "UNREADABLE"
    assert observation.error == "CDS query timed out"


def test_evaluate_cds_cds_only_is_found() -> None:
    observation = evaluate_cds(
        "example.com",
        cds_found=True,
        cdnskey_found=False,
        cds=(_cds_record(),),
    )
    assert observation.status == "FOUND"
    assert observation.cds_found is True
    assert observation.cdnskey_found is False


def test_parse_cds_truncates_after_eight() -> None:
    rdatas = [
        SimpleNamespace(key_tag=index, algorithm=13, digest_type=2)
        for index in range(9)
    ]
    parsed, truncated = parse_cds(rdatas)
    assert truncated is True
    assert len(parsed) == 8
    assert parsed[0].key_tag == 0
    assert parsed[-1].key_tag == 7


def test_parse_cdnskey_lists_algorithm() -> None:
    rdata = SimpleNamespace(flags=257, protocol=3, algorithm=15)
    parsed, truncated = parse_cdnskey((rdata,))
    assert truncated is False
    assert parsed[0].algorithm == 15
    assert "Ed25519" in parsed[0].algorithm_meaning
    assert parsed[0].role == "KSK"


def test_inspect_cds_uses_probe_results() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._dnssec_probe = MagicMock(  # type: ignore[method-assign]
        side_effect=[(True, False), (False, False)]
    )
    observation = resolver.inspect_cds("example.com")
    assert observation.status == "FOUND"
    assert observation.cds_found is True
    assert observation.cdnskey_found is False
    assert resolver._dnssec_probe.call_count == 2
    assert resolver._dnssec_probe.call_args_list[0].args[2] == "CDS"
    assert resolver._dnssec_probe.call_args_list[1].args[2] == "CDNSKEY"


def test_inspect_cds_parses_rdata() -> None:
    resolver = DNSResolver(timeout=1.0)
    cds = SimpleNamespace(key_tag=2371, algorithm=13, digest_type=2)
    key = SimpleNamespace(flags=257, protocol=3, algorithm=13)
    resolver._dnssec_probe = MagicMock(  # type: ignore[method-assign]
        side_effect=[(True, False, (cds,)), (True, False, (key,))]
    )
    observation = resolver.inspect_cds("Example.COM.")
    assert observation.status == "FOUND"
    assert observation.query_name == "example.com"
    assert observation.cds[0].digest_type == 2
    assert "SHA-256" in observation.cds[0].digest_meaning
    assert observation.cdnskey[0].algorithm == 13
    assert observation.cdnskey[0].role == "KSK"


def test_inspect_cds_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._dnssec_probe = MagicMock(return_value=(False, False, ()))  # type: ignore[method-assign]
    observation = resolver.inspect_cds("example.com")
    assert observation.status == "NOT DETECTED"


def test_inspect_cds_timeout_is_unreadable() -> None:
    resolver = DNSResolver(timeout=1.0)

    def probe(_client: object, _name: str, rdtype: str, errors: list[str]):
        errors.append(f"{rdtype} query timed out")
        return False, False, ()

    resolver._dnssec_probe = probe  # type: ignore[method-assign]
    observation = resolver.inspect_cds("example.com")
    assert observation.status == "UNREADABLE"
    assert observation.error is not None
    assert "CDS" in observation.error


def test_cds_missing_is_info_and_unscored() -> None:
    observation = evaluate_cds(
        "example.com", cds_found=False, cdnskey_found=False
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        cds=observation,
    )
    missing = next(item for item in report.findings if item.code == "cds_missing")
    assert missing.severity == "info"
    assert "broken DNSSEC" in missing.description
    assert WEIGHTS["cds_missing"] == 0
    assert report.risk.value == 0


def test_cds_timeout_is_info_unreadable() -> None:
    observation = evaluate_cds(
        "example.com",
        cds_found=False,
        cdnskey_found=False,
        error="CDS query timed out",
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        cds=observation,
    )
    unread = next(item for item in report.findings if item.code == "cds_unreadable")
    assert unread.severity == "info"
    assert not any(item.code == "cds_missing" for item in report.findings)
    assert report.risk.value == 0


def test_analyze_without_cds_stays_unchanged() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
    )
    assert not any(item.code.startswith("cds_") for item in report.findings)
    assert report.risk.value == 0
