"""DNSSEC observation and security analyzer tests. No network access."""

from unittest.mock import MagicMock

import dns.exception
import dns.flags
import dns.resolver

from analyzer.dmarc import evaluate_dmarc
from analyzer.dnssec import evaluate_dnssec
from analyzer.models import CoreLookup, DNSRecord
from analyzer.resolver import DNSResolver
from analyzer.security import SecurityAnalyzer
from analyzer.spf import inspect_spf


def test_evaluate_not_detected_without_keys() -> None:
    observation = evaluate_dnssec(dnskey_found=False, ds_found=False, ad_flag=False)
    assert observation.status == "NOT DETECTED"
    assert "compromised" in observation.note


def test_evaluate_detected_with_dnskey_only() -> None:
    observation = evaluate_dnssec(dnskey_found=True, ds_found=False, ad_flag=False)
    assert observation.status == "DETECTED"
    assert observation.dnskey_found is True
    assert observation.ds_found is False


def test_evaluate_detected_with_ds() -> None:
    observation = evaluate_dnssec(dnskey_found=False, ds_found=True, ad_flag=True)
    assert observation.status == "DETECTED"
    assert observation.ad_flag is True


def test_inspect_dnssec_uses_probe_results() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._dnssec_probe = MagicMock(side_effect=[(True, False), (True, True)])  # type: ignore[method-assign]

    observation = resolver.inspect_dnssec("example.com")

    assert observation.status == "DETECTED"
    assert observation.dnskey_found is True
    assert observation.ds_found is True
    assert observation.ad_flag is True


def test_dnssec_probe_timeout_is_not_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    client = MagicMock()
    client.resolve.side_effect = dns.exception.Timeout()
    errors: list[str] = []

    found, ad_flag = resolver._dnssec_probe(client, "example.com", "DNSKEY", errors)

    assert found is False
    assert ad_flag is False
    assert errors == ["DNSKEY query timed out"]


def test_dnssec_probe_reads_ad_flag() -> None:
    resolver = DNSResolver(timeout=1.0)
    answer = MagicMock()
    answer.response.flags = dns.flags.AD
    client = MagicMock()
    client.resolve.return_value = answer

    found, ad_flag = resolver._dnssec_probe(client, "example.com", "DS", [])

    assert found is True
    assert ad_flag is True
    client.resolve.assert_called_once_with("example.com", "DS", search=False)


def test_dnssec_probe_noanswer() -> None:
    resolver = DNSResolver(timeout=1.0)
    client = MagicMock()
    client.resolve.side_effect = dns.resolver.NoAnswer(
        response=type("R", (), {"question": "example.com IN DNSKEY"})()
    )
    errors: list[str] = []

    found, ad_flag = resolver._dnssec_probe(client, "example.com", "DNSKEY", errors)

    assert found is False
    assert ad_flag is False
    assert errors == []


def _lookup(
    *,
    a: list[DNSRecord] | None = None,
    aaaa: list[DNSRecord] | None = None,
    cname: list[DNSRecord] | None = None,
    txt: list[DNSRecord] | None = None,
    caa: list[DNSRecord] | None = None,
    errors: tuple[tuple[str, str], ...] = (),
) -> CoreLookup:
    return CoreLookup(
        a=tuple(a or []),
        aaaa=tuple(aaaa or []),
        cname=tuple(cname or []),
        mx=(),
        ns=(),
        txt=tuple(txt or []),
        soa=(),
        caa=tuple(caa or []),
        errors=errors,
    )


def _clean_lookup() -> CoreLookup:
    return _lookup(
        a=[DNSRecord("A", "example.com", "93.184.216.34", 300)],
        txt=[DNSRecord("TXT", "example.com", "v=spf1 -all", 300)],
        caa=[DNSRecord("CAA", "example.com", '0 issue "letsencrypt.org"', 3600)],
    )


def _titles(report) -> list[str]:
    return [finding.title for finding in report.findings]


def test_clean_configuration_has_no_findings() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
    )
    assert report.findings == ()
    assert report.highest_severity is None
    assert report.risk.value == 0
    assert report.risk.band == "LOW"


def test_missing_dmarc_is_low_not_high() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", []),
    )
    dmarc_findings = [item for item in report.findings if item.title == "DMARC not published"]
    assert len(dmarc_findings) == 1
    assert dmarc_findings[0].severity == "low"
    assert report.highest_severity == "low"
    assert all(item.severity != "high" for item in report.findings)
    assert all(item.severity != "critical" for item in report.findings)


def test_spf_plus_all_is_medium() -> None:
    lookup = _lookup(
        a=[DNSRecord("A", "example.com", "93.184.216.34", 300)],
        txt=[DNSRecord("TXT", "example.com", "v=spf1 +all", 300)],
        caa=[DNSRecord("CAA", "example.com", '0 issue "letsencrypt.org"', 3600)],
    )
    report = SecurityAnalyzer().analyze(
        lookup,
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(lookup.txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
    )
    titles = _titles(report)
    assert "SPF +all allows any sender" in titles
    plus_all = next(item for item in report.findings if "all" in item.title)
    assert plus_all.severity == "medium"
    assert report.highest_severity == "medium"


def test_private_address_is_medium() -> None:
    lookup = _lookup(
        a=[DNSRecord("A", "intranet.example", "10.0.0.5", 60)],
        txt=[DNSRecord("TXT", "intranet.example", "v=spf1 -all", 300)],
        caa=[DNSRecord("CAA", "intranet.example", '0 issue "letsencrypt.org"', 3600)],
    )
    report = SecurityAnalyzer().analyze(
        lookup,
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(lookup.txt),
        evaluate_dmarc("_dmarc.intranet.example", [
            DNSRecord("TXT", "_dmarc.intranet.example", "v=DMARC1; p=reject", 300),
        ]),
    )
    assert any("private" in item.title for item in report.findings)
    assert report.highest_severity == "medium"


def test_missing_dnssec_is_info_not_compromise() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=False, ds_found=False, ad_flag=False),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
    )
    dnssec_findings = [
        item for item in report.findings if "DNSSEC" in item.title
    ]
    assert len(dnssec_findings) == 1
    assert dnssec_findings[0].severity == "info"
    assert "compromised" not in dnssec_findings[0].title.lower()


def test_txt_timeout_is_info_not_missing_spf() -> None:
    lookup = _lookup(
        a=[DNSRecord("A", "example.com", "93.184.216.34", 300)],
        caa=[DNSRecord("CAA", "example.com", '0 issue "letsencrypt.org"', 3600)],
        errors=(("TXT", "DNS query timed out."),),
    )
    report = SecurityAnalyzer().analyze(
        lookup,
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(lookup.txt, lookup.errors),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
    )
    titles = _titles(report)
    assert "SPF could not be read" in titles
    assert "SPF not published" not in titles


def test_cname_without_address_is_low() -> None:
    lookup = _lookup(
        cname=[DNSRecord("CNAME", "www.example.com", "gone.example.net", 300)],
        txt=[DNSRecord("TXT", "www.example.com", "v=spf1 -all", 300)],
        caa=[DNSRecord("CAA", "www.example.com", '0 issue "letsencrypt.org"', 3600)],
    )
    report = SecurityAnalyzer().analyze(
        lookup,
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(lookup.txt),
        evaluate_dmarc("_dmarc.www.example.com", [
            DNSRecord("TXT", "_dmarc.www.example.com", "v=DMARC1; p=reject", 300),
        ]),
    )
    dangling = next(item for item in report.findings if "CNAME" in item.title)
    assert dangling.severity == "low"
    assert "takeover" in dangling.description.lower()
