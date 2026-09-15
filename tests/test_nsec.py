"""NSEC / NSEC3PARAM listing tests. No network access."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from analyzer.dmarc import evaluate_dmarc
from analyzer.dnssec import evaluate_dnssec
from analyzer.models import CoreLookup, DNSRecord
from analyzer.nsec import (
    Nsec3ParamRecord,
    NsecRecord,
    evaluate_nsec,
    parse_nsec,
    parse_nsec3param,
)
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


def _nsec_record(**overrides) -> NsecRecord:
    values = {
        "next_name": "www.example.com",
        "types": ("A", "NS", "SOA", "DNSKEY", "NSEC", "RRSIG"),
        "types_truncated": False,
    }
    values.update(overrides)
    return NsecRecord(**values)


def _nsec3param_record(**overrides) -> Nsec3ParamRecord:
    values = {
        "algorithm": 1,
        "algorithm_meaning": "SHA-1 (NSEC3 hash)",
        "flags": 1,
        "opt_out": True,
        "iterations": 0,
        "salt_length": 8,
        "iterations_note": "0 iterations (RFC 9276)",
    }
    values.update(overrides)
    return Nsec3ParamRecord(**values)


def test_evaluate_nsec_found_lists_next_name() -> None:
    observation = evaluate_nsec(
        "example.com",
        nsec_found=True,
        nsec3param_found=False,
        nsec=(_nsec_record(),),
    )
    assert observation.status == "FOUND"
    assert observation.nsec[0].next_name == "www.example.com"
    assert "A" in observation.nsec[0].types
    assert "walk" in observation.note
    assert "broken DNSSEC" in observation.note


def test_evaluate_nsec3param_found() -> None:
    observation = evaluate_nsec(
        "example.com",
        nsec_found=False,
        nsec3param_found=True,
        nsec3param=(_nsec3param_record(),),
    )
    assert observation.status == "FOUND"
    assert observation.nsec3param_found is True
    assert observation.nsec3param[0].algorithm == 1
    assert observation.nsec3param[0].opt_out is True
    assert observation.nsec3param[0].iterations == 0


def test_evaluate_nsec_not_detected() -> None:
    observation = evaluate_nsec(
        "example.com", nsec_found=False, nsec3param_found=False
    )
    assert observation.status == "NOT DETECTED"
    assert observation.nsec == ()
    assert observation.nsec3param == ()


def test_evaluate_nsec_timeout_is_unreadable() -> None:
    observation = evaluate_nsec(
        "example.com",
        nsec_found=False,
        nsec3param_found=False,
        error="NSEC3PARAM query timed out",
    )
    assert observation.status == "UNREADABLE"
    assert observation.error == "NSEC3PARAM query timed out"


def test_parse_nsec_truncates_after_eight() -> None:
    rdatas = [
        SimpleNamespace(next=f"n{index}.example.com.", types=("A",))
        for index in range(9)
    ]
    parsed, truncated = parse_nsec(rdatas)
    assert truncated is True
    assert len(parsed) == 8
    assert parsed[0].next_name == "n0.example.com"
    assert parsed[-1].next_name == "n7.example.com"


def test_parse_nsec3param_lists_algorithm_and_salt_length() -> None:
    rdata = SimpleNamespace(algorithm=1, flags=0, iterations=0, salt=b"\x00" * 4)
    parsed, truncated = parse_nsec3param((rdata,))
    assert truncated is False
    assert parsed[0].algorithm == 1
    assert "SHA-1" in parsed[0].algorithm_meaning
    assert parsed[0].opt_out is False
    assert parsed[0].salt_length == 4
    assert parsed[0].iterations == 0


def test_parse_nsec3param_nonzero_iterations_is_labeled() -> None:
    rdata = SimpleNamespace(algorithm=1, flags=0, iterations=10, salt=b"")
    parsed, _truncated = parse_nsec3param((rdata,))
    assert parsed[0].iterations == 10
    assert "RFC 9276" in parsed[0].iterations_note
    assert "compromise" in parsed[0].iterations_note


def test_inspect_nsec_uses_probe_results() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._dnssec_probe = MagicMock(  # type: ignore[method-assign]
        side_effect=[(True, False), (False, False)]
    )
    observation = resolver.inspect_nsec("example.com")
    assert observation.status == "FOUND"
    assert observation.nsec3param_found is True
    assert observation.nsec_found is False
    assert resolver._dnssec_probe.call_count == 2
    assert resolver._dnssec_probe.call_args_list[0].args[2] == "NSEC3PARAM"
    assert resolver._dnssec_probe.call_args_list[1].args[2] == "NSEC"


def test_inspect_nsec_parses_rdata() -> None:
    resolver = DNSResolver(timeout=1.0)
    param = SimpleNamespace(algorithm=1, flags=1, iterations=0, salt=b"abcd1234")
    nsec = SimpleNamespace(
        next="www.example.com.",
        types=("A", "NS", "SOA", "DNSKEY", "NSEC", "RRSIG"),
    )
    resolver._dnssec_probe = MagicMock(  # type: ignore[method-assign]
        side_effect=[(True, False, (param,)), (True, False, (nsec,))]
    )
    observation = resolver.inspect_nsec("Example.COM.")
    assert observation.status == "FOUND"
    assert observation.query_name == "example.com"
    assert observation.nsec3param[0].opt_out is True
    assert observation.nsec3param[0].salt_length == 8
    assert observation.nsec[0].next_name == "www.example.com"
    assert "DNSKEY" in observation.nsec[0].types


def test_inspect_nsec_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._dnssec_probe = MagicMock(return_value=(False, False, ()))  # type: ignore[method-assign]
    observation = resolver.inspect_nsec("example.com")
    assert observation.status == "NOT DETECTED"


def test_inspect_nsec_timeout_is_unreadable() -> None:
    resolver = DNSResolver(timeout=1.0)

    def probe(_client: object, _name: str, rdtype: str, errors: list[str]):
        errors.append(f"{rdtype} query timed out")
        return False, False, ()

    resolver._dnssec_probe = probe  # type: ignore[method-assign]
    observation = resolver.inspect_nsec("example.com")
    assert observation.status == "UNREADABLE"
    assert observation.error is not None
    assert "NSEC3PARAM" in observation.error


def test_nsec_missing_is_info_and_unscored() -> None:
    observation = evaluate_nsec(
        "example.com", nsec_found=False, nsec3param_found=False
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        nsec=observation,
    )
    missing = next(item for item in report.findings if item.code == "nsec_missing")
    assert missing.severity == "info"
    assert "broken DNSSEC" in missing.description
    assert WEIGHTS["nsec_missing"] == 0
    assert report.risk.value == 0


def test_nsec_timeout_is_info_unreadable() -> None:
    observation = evaluate_nsec(
        "example.com",
        nsec_found=False,
        nsec3param_found=False,
        error="NSEC query timed out",
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
        nsec=observation,
    )
    unread = next(item for item in report.findings if item.code == "nsec_unreadable")
    assert unread.severity == "info"
    assert not any(item.code == "nsec_missing" for item in report.findings)
    assert report.risk.value == 0


def test_analyze_without_nsec_stays_unchanged() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc(
            "_dmarc.example.com",
            [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
        ),
    )
    assert not any(item.code.startswith("nsec_") for item in report.findings)
    assert report.risk.value == 0
