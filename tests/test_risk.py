"""Risk score heuristic tests. No network access."""

from analyzer.dmarc import evaluate_dmarc
from analyzer.dnssec import evaluate_dnssec
from analyzer.models import CoreLookup, DNSRecord
from analyzer.risk import WEIGHTS, band_for, score_risk
from analyzer.security import SecurityAnalyzer, SecurityFinding
from analyzer.spf import inspect_spf


def _lookup(
    *,
    a: list[DNSRecord] | None = None,
    txt: list[DNSRecord] | None = None,
    caa: list[DNSRecord] | None = None,
    errors: tuple[tuple[str, str], ...] = (),
) -> CoreLookup:
    return CoreLookup(
        a=tuple(a or []),
        aaaa=(),
        cname=(),
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


def _reject_dmarc():
    return evaluate_dmarc(
        "_dmarc.example.com",
        [DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300)],
    )


def test_band_boundaries() -> None:
    assert band_for(0) == "LOW"
    assert band_for(20) == "LOW"
    assert band_for(21) == "MEDIUM"
    assert band_for(50) == "MEDIUM"
    assert band_for(51) == "HIGH"
    assert band_for(75) == "HIGH"
    assert band_for(76) == "CRITICAL"
    assert band_for(100) == "CRITICAL"


def test_clean_report_scores_zero() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        _reject_dmarc(),
    )
    assert report.risk.value == 0
    assert report.risk.band == "LOW"
    assert report.risk.contributions == ()


def test_missing_dmarc_adds_ten() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", []),
    )
    assert report.risk.value == WEIGHTS["dmarc_missing"]
    assert report.risk.band == "LOW"
    assert report.risk.contributions[0].code == "dmarc_missing"
    assert report.risk.contributions[0].points == 10


def test_dnssec_absence_is_lighter_than_missing_dmarc() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=False, ds_found=False, ad_flag=False),
        inspect_spf(_clean_lookup().txt),
        _reject_dmarc(),
    )
    assert report.risk.value == WEIGHTS["dnssec_not_detected"]
    assert report.risk.value < WEIGHTS["dmarc_missing"]
    assert report.risk.band == "LOW"


def test_plus_all_reaches_medium_alone() -> None:
    lookup = _lookup(
        a=[DNSRecord("A", "example.com", "93.184.216.34", 300)],
        txt=[DNSRecord("TXT", "example.com", "v=spf1 +all", 300)],
        caa=[DNSRecord("CAA", "example.com", '0 issue "letsencrypt.org"', 3600)],
    )
    report = SecurityAnalyzer().analyze(
        lookup,
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(lookup.txt),
        _reject_dmarc(),
    )
    assert report.risk.value == WEIGHTS["spf_plus_all"]
    assert report.risk.band == "MEDIUM"


def test_spf_timeout_is_not_scored_as_missing() -> None:
    lookup = _lookup(
        a=[DNSRecord("A", "example.com", "93.184.216.34", 300)],
        caa=[DNSRecord("CAA", "example.com", '0 issue "letsencrypt.org"', 3600)],
        errors=(("TXT", "DNS query timed out."),),
    )
    report = SecurityAnalyzer().analyze(
        lookup,
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(lookup.txt, lookup.errors),
        _reject_dmarc(),
    )
    assert report.risk.value == 0
    assert all(item.code != "spf_missing" for item in report.risk.contributions)


def test_contributions_sum_to_value() -> None:
    report = SecurityAnalyzer().analyze(
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        evaluate_dnssec(dnskey_found=False, ds_found=False, ad_flag=False),
        inspect_spf(()),
        evaluate_dmarc("_dmarc.example.com", []),
    )
    summed = sum(item.points for item in report.risk.contributions)
    assert report.risk.value == summed
    assert report.risk.value == (
        WEIGHTS["dnssec_not_detected"]
        + WEIGHTS["spf_missing"]
        + WEIGHTS["dmarc_missing"]
        + WEIGHTS["caa_missing"]
    )
    assert report.risk.band == "MEDIUM"


def test_unknown_code_adds_zero() -> None:
    finding = SecurityFinding(
        severity="info",
        title="ignored",
        description="x",
        recommendation="x",
        code="not_a_real_code",
    )
    risk = score_risk([finding])
    assert risk.value == 0
    assert risk.contributions == ()


def test_score_is_capped_at_100() -> None:
    heavy = SecurityFinding(
        severity="medium",
        title="A points to a private address",
        description="x",
        recommendation="x",
        code="address_non_global",
    )
    risk = score_risk([heavy] * 10)
    assert risk.raw_total == WEIGHTS["address_non_global"] * 10
    assert risk.value == 100
    assert risk.capped is True
    assert risk.band == "CRITICAL"
