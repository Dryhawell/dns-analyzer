"""ZONEMD listing tests. No network access."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from analyzer.dmarc import evaluate_dmarc
from analyzer.dnssec import evaluate_dnssec
from analyzer.models import CoreLookup, DNSRecord
from analyzer.resolver import DNSResolver
from analyzer.risk import WEIGHTS
from analyzer.security import SecurityAnalyzer
from analyzer.spf import inspect_spf
from analyzer.zonemd import ZonemdRecord, evaluate_zonemd, parse_zonemd


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


def _zonemd_record(**overrides) -> ZonemdRecord:
    values = {
        "serial": 2026091601,
        "scheme": 1,
        "scheme_meaning": "SIMPLE",
        "hash_algorithm": 1,
        "hash_meaning": "SHA-384",
        "digest_length": 48,
    }
    values.update(overrides)
    return ZonemdRecord(**values)


def test_evaluate_zonemd_found_lists_scheme_and_hash() -> None:
    observation = evaluate_zonemd(
        "example.com",
        found=True,
        zonemd=(_zonemd_record(),),
    )
    assert observation.status == "FOUND"
    assert observation.zonemd[0].scheme == 1
    assert observation.zonemd[0].hash_algorithm == 1
    assert "SHA-384" in observation.zonemd[0].hash_meaning
    assert "AXFR" in observation.note
    assert "broken DNSSEC" in observation.note


def test_evaluate_zonemd_not_detected() -> None:
    observation = evaluate_zonemd("example.com", found=False)
    assert observation.status == "NOT DETECTED"
    assert observation.zonemd == ()


def test_evaluate_zonemd_timeout_is_unreadable() -> None:
    observation = evaluate_zonemd(
        "example.com",
        found=False,
        error="ZONEMD query timed out",
    )
    assert observation.status == "UNREADABLE"
    assert observation.error == "ZONEMD query timed out"


def test_parse_zonemd_truncates_after_eight() -> None:
    rdatas = [
        SimpleNamespace(
            serial=index, scheme=1, hash_algorithm=1, digest=b"\x00" * 48
        )
        for index in range(9)
    ]
    parsed, truncated = parse_zonemd(rdatas)
    assert truncated is True
    assert len(parsed) == 8
    assert parsed[0].serial == 0
    assert parsed[-1].serial == 7


def test_parse_zonemd_digest_length_without_dumping_bytes() -> None:
    rdata = SimpleNamespace(
        serial=1, scheme=1, hash_algorithm=2, digest=b"\xab" * 64
    )
    parsed, truncated = parse_zonemd((rdata,))
    assert truncated is False
    assert parsed[0].hash_meaning == "SHA-512"
    assert parsed[0].digest_length == 64
    assert parsed[0].scheme_meaning == "SIMPLE"


def test_inspect_zonemd_uses_probe_results() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._dnssec_probe = MagicMock(  # type: ignore[method-assign]
        return_value=(True, False)
    )
    observation = resolver.inspect_zonemd("example.com")
    assert observation.status == "FOUND"
    assert resolver._dnssec_probe.call_count == 1
    assert resolver._dnssec_probe.call_args.args[2] == "ZONEMD"


def test_inspect_zonemd_parses_rdata() -> None:
    resolver = DNSResolver(timeout=1.0)
    rdata = SimpleNamespace(
        serial=2026091601, scheme=1, hash_algorithm=1, digest=b"\x00" * 48
    )
    resolver._dnssec_probe = MagicMock(  # type: ignore[method-assign]
        return_value=(True, False, (rdata,))
    )
    observation = resolver.inspect_zonemd("Example.COM.")
    assert observation.status == "FOUND"
    assert observation.query_name == "example.com"
    assert observation.zonemd[0].serial == 2026091601
    assert observation.zonemd[0].digest_length == 48
    assert "SHA-384" in observation.zonemd[0].hash_meaning


def test_inspect_zonemd_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._dnssec_probe = MagicMock(return_value=(False, False, ()))  # type: ignore[method-assign]
    observation = resolver.inspect_zonemd("example.com")
    assert observation.status == "NOT DETECTED"


def test_inspect_zonemd_timeout_is_unreadable() -> None:
    resolver = DNSResolver(timeout=1.0)

    def probe(_client: object, _name: str, rdtype: str, errors: list[str]):
        errors.append(f"{rdtype} query timed out")
        return False, False, ()

    resolver._dnssec_probe = probe  # type: ignore[method-assign]
    observation = resolver.inspect_zonemd("example.com")
    assert observation.status == "UNREADABLE"
    assert observation.error is not None
    assert "ZONEMD" in observation.error


def test_zonemd_missing_is_info_and_unscored() -> None:
    observation = evaluate_zonemd("example.com", found=False)
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        zonemd=observation,
    )
    missing = next(item for item in report.findings if item.code == "zonemd_missing")
    assert missing.severity == "info"
    assert "broken DNSSEC" in missing.description
    assert WEIGHTS["zonemd_missing"] == 0
    assert report.risk.value == 0


def test_zonemd_timeout_is_info_unreadable() -> None:
    observation = evaluate_zonemd(
        "example.com",
        found=False,
        error="ZONEMD query timed out",
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        zonemd=observation,
    )
    unread = next(item for item in report.findings if item.code == "zonemd_unreadable")
    assert unread.severity == "info"
    assert not any(item.code == "zonemd_missing" for item in report.findings)
    assert report.risk.value == 0


def test_analyze_without_zonemd_stays_unchanged() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
    )
    assert not any(item.code.startswith("zonemd_") for item in report.findings)
    assert report.risk.value == 0
