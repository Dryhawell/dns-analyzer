"""DNSSEC observation and security analyzer tests. No network access."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import dns.exception
import dns.flags
import dns.resolver

from analyzer.dmarc import evaluate_dmarc
from analyzer.dnssec import DnssecDelegation, DnssecKey, evaluate_dnssec
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

    found, ad_flag, records = resolver._dnssec_probe(client, "example.com", "DNSKEY", errors)

    assert found is False
    assert ad_flag is False
    assert records == ()
    assert errors == ["DNSKEY query timed out"]


def test_dnssec_probe_reads_ad_flag() -> None:
    resolver = DNSResolver(timeout=1.0)
    answer = MagicMock()
    answer.response.flags = dns.flags.AD
    client = MagicMock()
    client.resolve.return_value = answer

    found, ad_flag, records = resolver._dnssec_probe(client, "example.com", "DS", [])

    assert found is True
    assert ad_flag is True
    assert records == ()
    client.resolve.assert_called_once_with("example.com", "DS", search=False)


def test_dnssec_probe_noanswer() -> None:
    resolver = DNSResolver(timeout=1.0)
    client = MagicMock()
    client.resolve.side_effect = dns.resolver.NoAnswer(
        response=type("R", (), {"question": "example.com IN DNSKEY"})()
    )
    errors: list[str] = []

    found, ad_flag, records = resolver._dnssec_probe(client, "example.com", "DNSKEY", errors)

    assert found is False
    assert ad_flag is False
    assert records == ()
    assert errors == []


def _dnssec_key(**overrides) -> DnssecKey:
    values = {
        "flags": 257,
        "protocol": 3,
        "algorithm": 15,
        "algorithm_meaning": "Ed25519",
        "role": "KSK",
        "zone_key": True,
        "secure_entry_point": True,
        "key_tag": 12345,
    }
    values.update(overrides)
    return DnssecKey(**values)


def _dnssec_ds(**overrides) -> DnssecDelegation:
    values = {
        "key_tag": 2371,
        "algorithm": 13,
        "algorithm_meaning": "ECDSAP256SHA256",
        "digest_type": 2,
        "digest_meaning": "SHA-256",
    }
    values.update(overrides)
    return DnssecDelegation(**values)


def test_evaluate_dnssec_lists_key_algorithms() -> None:
    observation = evaluate_dnssec(
        dnskey_found=True,
        ds_found=True,
        ad_flag=True,
        keys=(_dnssec_key(),),
        delegations=(_dnssec_ds(),),
    )
    assert observation.status == "DETECTED"
    assert observation.keys[0].algorithm == 15
    assert observation.keys[0].algorithm_meaning == "Ed25519"
    assert observation.keys[0].role == "KSK"
    assert observation.delegations[0].digest_type == 2
    assert observation.delegations[0].digest_meaning == "SHA-256"


def test_inspect_dnssec_parses_key_algorithms() -> None:
    resolver = DNSResolver(timeout=1.0)
    key = SimpleNamespace(flags=257, protocol=3, algorithm=15)
    ds = SimpleNamespace(key_tag=2371, algorithm=13, digest_type=2)
    resolver._dnssec_probe = MagicMock(  # type: ignore[method-assign]
        side_effect=[(True, False, (key,)), (True, True, (ds,))]
    )

    observation = resolver.inspect_dnssec("example.com")

    assert observation.status == "DETECTED"
    assert observation.keys[0].algorithm == 15
    assert "Ed25519" in observation.keys[0].algorithm_meaning
    assert observation.keys[0].role == "KSK"
    assert observation.delegations[0].digest_type == 2
    assert "SHA-256" in observation.delegations[0].digest_meaning


def test_dnssec_probe_collects_integer_rdatas() -> None:
    resolver = DNSResolver(timeout=1.0)
    key = SimpleNamespace(flags=256, protocol=3, algorithm=8)

    class _Answer:
        def __init__(self) -> None:
            self.response = SimpleNamespace(flags=0)

        def __iter__(self):
            return iter([key])

    client = MagicMock()
    client.resolve.return_value = _Answer()

    found, ad_flag, records = resolver._dnssec_probe(client, "example.com", "DNSKEY", [])

    assert found is True
    assert ad_flag is False
    assert records == (key,)


def test_sha1_dnskey_algorithm_is_info_not_compromise() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(
            dnskey_found=True,
            ds_found=True,
            ad_flag=True,
            keys=(_dnssec_key(algorithm=5, algorithm_meaning="RSA/SHA-1", role="ZSK"),),
            delegations=(_dnssec_ds(digest_type=1, digest_meaning="SHA-1"),),
        ),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
    )
    codes = [item.code for item in report.findings]
    assert "dnssec_sha1_algorithm" in codes
    assert "dnssec_sha1_ds" in codes
    algo = next(item for item in report.findings if item.code == "dnssec_sha1_algorithm")
    digest = next(item for item in report.findings if item.code == "dnssec_sha1_ds")
    assert algo.severity == "info"
    assert digest.severity == "info"
    assert "not proof" in algo.description.lower()
    assert "compromised" in algo.description.lower()
    assert report.risk.value == 0


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


def test_cname_not_dangling_when_aaaa_timed_out() -> None:
    lookup = _lookup(
        cname=[DNSRecord("CNAME", "www.example.com", "target.example.net", 300)],
        txt=[DNSRecord("TXT", "www.example.com", "v=spf1 -all", 300)],
        caa=[DNSRecord("CAA", "www.example.com", '0 issue "letsencrypt.org"', 3600)],
        errors=(("AAAA", "DNS query timed out."),),
    )
    report = SecurityAnalyzer().analyze(
        lookup,
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(lookup.txt),
        evaluate_dmarc("_dmarc.www.example.com", [
            DNSRecord("TXT", "_dmarc.www.example.com", "v=DMARC1; p=reject", 300),
        ]),
    )
    assert all("CNAME" not in item.title for item in report.findings)


def test_documentation_address_is_not_scored_as_private() -> None:
    lookup = _lookup(
        a=[DNSRecord("A", "example.com", "192.0.2.1", 300)],
        txt=[DNSRecord("TXT", "example.com", "v=spf1 -all", 300)],
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
    assert all(item.code != "address_non_global" for item in report.findings)


def test_missing_caa_is_info() -> None:
    lookup = _lookup(
        a=[DNSRecord("A", "example.com", "93.184.216.34", 300)],
        txt=[DNSRecord("TXT", "example.com", "v=spf1 -all", 300)],
    )
    report = SecurityAnalyzer().analyze(
        lookup,
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(lookup.txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
    )
    caa = next(item for item in report.findings if item.code == "caa_missing")
    assert caa.severity == "info"


def test_dmarc_p_none_is_info() -> None:
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=none", 300),
        ]),
    )
    none = next(item for item in report.findings if item.code == "dmarc_p_none")
    assert none.severity == "info"
    assert report.highest_severity == "info"


def test_many_txt_records_are_info() -> None:
    txt = [DNSRecord("TXT", "example.com", f"token-{index}", 300) for index in range(9)]
    txt[0] = DNSRecord("TXT", "example.com", "v=spf1 -all", 300)
    lookup = _lookup(
        a=[DNSRecord("A", "example.com", "93.184.216.34", 300)],
        txt=txt,
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
    volume = next(item for item in report.findings if item.code == "txt_many")
    assert volume.severity == "info"


def test_dkim_revoked_is_medium_not_high() -> None:
    from analyzer.dkim import evaluate_dkim

    observation = evaluate_dkim(
        "google._domainkey.example.com",
        "google",
        [DNSRecord("TXT", "google._domainkey.example.com", "v=DKIM1; p=", 300)],
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        (observation,),
    )
    revoked = next(item for item in report.findings if item.code == "dkim_revoked")
    assert revoked.severity == "medium"
    assert report.highest_severity == "medium"
    assert not any(item.severity == "high" for item in report.findings)


def test_dkim_missing_selector_is_info_and_unscored() -> None:
    from analyzer.dkim import evaluate_dkim
    from analyzer.risk import WEIGHTS

    observation = evaluate_dkim("google._domainkey.example.com", "google", ())
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        (observation,),
    )
    missing = next(item for item in report.findings if item.code == "dkim_selector_missing")
    assert missing.severity == "info"
    assert WEIGHTS["dkim_selector_missing"] == 0
    assert report.risk.value == 0


def test_srv_missing_is_info_and_unscored() -> None:
    from analyzer.risk import WEIGHTS
    from analyzer.srv import SrvSpec, evaluate_srv

    observation = evaluate_srv("_sip._tcp.example.com", SrvSpec("sip", "tcp"), ())
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        (),
        (observation,),
    )
    missing = next(item for item in report.findings if item.code == "srv_missing")
    assert missing.severity == "info"
    assert WEIGHTS["srv_missing"] == 0
    assert report.risk.value == 0


def test_srv_timeout_is_info_unreadable() -> None:
    from analyzer.srv import SrvSpec, evaluate_srv

    observation = evaluate_srv(
        "_sip._tcp.example.com",
        SrvSpec("sip", "tcp"),
        (),
        error="DNS query timed out.",
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        srv=(observation,),
    )
    unread = next(item for item in report.findings if item.code == "srv_unreadable")
    assert unread.severity == "info"
    assert not any(item.code == "srv_missing" for item in report.findings)


def test_naptr_missing_is_info_and_unscored() -> None:
    from analyzer.risk import WEIGHTS
    from analyzer.naptr import evaluate_naptr

    observation = evaluate_naptr("example.com", ())
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        naptr=observation,
    )
    missing = next(item for item in report.findings if item.code == "naptr_missing")
    assert missing.severity == "info"
    assert WEIGHTS["naptr_missing"] == 0
    assert report.risk.value == 0


def test_naptr_timeout_is_info_unreadable() -> None:
    from analyzer.naptr import evaluate_naptr

    observation = evaluate_naptr("example.com", (), error="DNS query timed out.")
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        naptr=observation,
    )
    unread = next(item for item in report.findings if item.code == "naptr_unreadable")
    assert unread.severity == "info"
    assert not any(item.code == "naptr_missing" for item in report.findings)
    assert report.risk.value == 0


def test_mta_sts_missing_is_info_and_unscored() -> None:
    from analyzer.mtasts import evaluate_mta_sts
    from analyzer.risk import WEIGHTS

    observation = evaluate_mta_sts("_mta-sts.example.com", "mta-sts.example.com", ())
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        mta_sts=observation,
    )
    missing = next(item for item in report.findings if item.code == "mtasts_missing")
    assert missing.severity == "info"
    assert WEIGHTS["mtasts_missing"] == 0
    assert report.risk.value == 0


def test_mta_sts_found_with_id_adds_no_points() -> None:
    from analyzer.mtasts import evaluate_mta_sts

    observation = evaluate_mta_sts(
        "_mta-sts.example.com",
        "mta-sts.example.com",
        [DNSRecord("TXT", "_mta-sts.example.com", "v=STSv1; id=abc", 300)],
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        mta_sts=observation,
    )
    assert not any(item.code.startswith("mtasts_") for item in report.findings)
    assert report.risk.value == 0


def test_tls_rpt_missing_is_info_and_unscored() -> None:
    from analyzer.risk import WEIGHTS
    from analyzer.tlsrpt import evaluate_tls_rpt

    observation = evaluate_tls_rpt("_smtp._tls.example.com", ())
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        tls_rpt=observation,
    )
    missing = next(item for item in report.findings if item.code == "tlsrpt_missing")
    assert missing.severity == "info"
    assert WEIGHTS["tlsrpt_missing"] == 0
    assert report.risk.value == 0


def test_tls_rpt_found_with_rua_adds_no_points() -> None:
    from analyzer.tlsrpt import evaluate_tls_rpt

    observation = evaluate_tls_rpt(
        "_smtp._tls.example.com",
        [DNSRecord("TXT", "_smtp._tls.example.com", "v=TLSRPTv1; rua=mailto:tlsrpt@example.com", 300)],
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        tls_rpt=observation,
    )
    assert not any(item.code.startswith("tlsrpt_") for item in report.findings)
    assert report.risk.value == 0


def test_bimi_missing_is_info_and_unscored() -> None:
    from analyzer.bimi import evaluate_bimi
    from analyzer.risk import WEIGHTS

    observation = evaluate_bimi("default._bimi.example.com", "default", ())
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        bimi=observation,
    )
    missing = next(item for item in report.findings if item.code == "bimi_missing")
    assert missing.severity == "info"
    assert WEIGHTS["bimi_missing"] == 0
    assert report.risk.value == 0


def test_bimi_found_with_location_and_enforcing_dmarc_adds_no_points() -> None:
    from analyzer.bimi import evaluate_bimi

    observation = evaluate_bimi(
        "default._bimi.example.com",
        "default",
        [DNSRecord("TXT", "default._bimi.example.com", "v=BIMI1; l=https://example.com/logo.svg", 300)],
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        bimi=observation,
    )
    assert not any(item.code.startswith("bimi_") for item in report.findings)
    assert report.risk.value == 0


def test_bimi_found_without_enforcing_dmarc_is_info() -> None:
    from analyzer.bimi import evaluate_bimi

    observation = evaluate_bimi(
        "default._bimi.example.com",
        "default",
        [DNSRecord("TXT", "default._bimi.example.com", "v=BIMI1; l=https://example.com/logo.svg", 300)],
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=none", 300),
        ]),
        bimi=observation,
    )
    finding = next(item for item in report.findings if item.code == "bimi_without_enforcing_dmarc")
    assert finding.severity == "info"
    from analyzer.risk import WEIGHTS
    assert WEIGHTS["bimi_without_enforcing_dmarc"] == 0


def test_tlsa_missing_is_info_and_unscored() -> None:
    from analyzer.risk import WEIGHTS
    from analyzer.tlsa import evaluate_tlsa

    observation = evaluate_tlsa("_443._tcp.example.com", ())
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        tlsa=observation,
    )
    missing = next(item for item in report.findings if item.code == "tlsa_missing")
    assert missing.severity == "info"
    assert WEIGHTS["tlsa_missing"] == 0
    assert report.risk.value == 0


def test_tlsa_found_adds_no_points() -> None:
    from analyzer.tlsa import evaluate_tlsa

    observation = evaluate_tlsa(
        "_443._tcp.example.com",
        [
            DNSRecord(
                "TLSA",
                "_443._tcp.example.com",
                "3 1 1 " + "ab" * 32,
                300,
                details=(
                    ("Usage", "3 — DANE-EE"),
                    ("Selector", "1 — SPKI"),
                    ("Matching", "1 — SHA-256"),
                    ("Association", "ab" * 32),
                ),
            )
        ],
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        tlsa=observation,
    )
    assert not any(item.code.startswith("tlsa_") for item in report.findings)
    assert report.risk.value == 0


def test_sshfp_missing_is_info_and_unscored() -> None:
    from analyzer.risk import WEIGHTS
    from analyzer.sshfp import evaluate_sshfp

    observation = evaluate_sshfp("example.com", ())
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        sshfp=observation,
    )
    missing = next(item for item in report.findings if item.code == "sshfp_missing")
    assert missing.severity == "info"
    assert WEIGHTS["sshfp_missing"] == 0
    assert report.risk.value == 0


def test_sshfp_found_adds_no_points() -> None:
    from analyzer.sshfp import evaluate_sshfp

    observation = evaluate_sshfp(
        "example.com",
        [
            DNSRecord(
                "SSHFP",
                "example.com",
                "4 2 " + "ab" * 32,
                300,
                details=(
                    ("Algorithm", "4 — Ed25519"),
                    ("Fingerprint type", "2 — SHA-256"),
                    ("Fingerprint", "ab" * 32),
                ),
            )
        ],
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        sshfp=observation,
    )
    assert not any(item.code.startswith("sshfp_") for item in report.findings)
    assert report.risk.value == 0


def test_fcrdns_no_ptr_is_info_and_unscored() -> None:
    from analyzer.fcrdns import FcrdnsCheck, evaluate_fcrdns
    from analyzer.risk import WEIGHTS

    observation = evaluate_fcrdns(
        [
            FcrdnsCheck(
                ip="93.184.216.34",
                ptr_query="34.216.184.93.in-addr.arpa",
                ptr_names=(),
                forward_ips=(),
                status="NO PTR",
            )
        ]
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        fcrdns=observation,
    )
    missing = next(item for item in report.findings if item.code == "fcrdns_no_ptr")
    assert missing.severity == "info"
    assert WEIGHTS["fcrdns_no_ptr"] == 0
    assert report.risk.value == 0


def test_fcrdns_mismatch_is_info_and_unscored() -> None:
    from analyzer.fcrdns import FcrdnsCheck, evaluate_fcrdns
    from analyzer.risk import WEIGHTS

    observation = evaluate_fcrdns(
        [
            FcrdnsCheck(
                ip="93.184.216.34",
                ptr_query="34.216.184.93.in-addr.arpa",
                ptr_names=("other.example",),
                forward_ips=("192.0.2.1",),
                status="MISMATCH",
            )
        ]
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        fcrdns=observation,
    )
    mismatch = next(item for item in report.findings if item.code == "fcrdns_mismatch")
    assert mismatch.severity == "info"
    assert WEIGHTS["fcrdns_mismatch"] == 0
    assert report.risk.value == 0


def test_fcrdns_confirmed_adds_no_points() -> None:
    from analyzer.fcrdns import FcrdnsCheck, evaluate_fcrdns

    observation = evaluate_fcrdns(
        [
            FcrdnsCheck(
                ip="93.184.216.34",
                ptr_query="34.216.184.93.in-addr.arpa",
                ptr_names=("example.com",),
                forward_ips=("93.184.216.34",),
                status="CONFIRMED",
            )
        ]
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        fcrdns=observation,
    )
    assert not any(item.code.startswith("fcrdns_") for item in report.findings)
    assert report.risk.value == 0


def test_mx_host_nxdomain_is_info_and_unscored() -> None:
    from analyzer.mx import MxHostCheck, evaluate_mx_hosts
    from analyzer.risk import WEIGHTS

    observation = evaluate_mx_hosts(
        "example.com",
        [
            MxHostCheck(
                host="gone.example.net",
                preference=10,
                ipv4=(),
                ipv6=(),
                status="NXDOMAIN",
            )
        ],
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        mx_hosts=observation,
    )
    missing = next(item for item in report.findings if item.code == "mx_host_nxdomain")
    assert missing.severity == "info"
    assert WEIGHTS["mx_host_nxdomain"] == 0
    assert report.risk.value == 0


def test_mx_host_no_address_is_info_and_unscored() -> None:
    from analyzer.mx import MxHostCheck, evaluate_mx_hosts
    from analyzer.risk import WEIGHTS

    observation = evaluate_mx_hosts(
        "example.com",
        [
            MxHostCheck(
                host="mail.example.com",
                preference=10,
                ipv4=(),
                ipv6=(),
                status="NO ADDRESS",
            )
        ],
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        mx_hosts=observation,
    )
    empty = next(item for item in report.findings if item.code == "mx_host_no_address")
    assert empty.severity == "info"
    assert WEIGHTS["mx_host_no_address"] == 0
    assert report.risk.value == 0


def test_mx_host_resolves_adds_no_points() -> None:
    from analyzer.mx import MxHostCheck, evaluate_mx_hosts

    observation = evaluate_mx_hosts(
        "example.com",
        [
            MxHostCheck(
                host="mail.example.com",
                preference=10,
                ipv4=("192.0.2.10",),
                ipv6=(),
                status="RESOLVES",
            )
        ],
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        mx_hosts=observation,
    )
    assert not any(item.code.startswith("mx_") for item in report.findings)
    assert report.risk.value == 0


def test_ns_host_nxdomain_is_info_and_unscored() -> None:
    from analyzer.ns import NsHostCheck, evaluate_ns_hosts
    from analyzer.risk import WEIGHTS

    observation = evaluate_ns_hosts(
        "example.com",
        [
            NsHostCheck(
                host="gone.example.net",
                in_bailiwick=False,
                ipv4=(),
                ipv6=(),
                status="NXDOMAIN",
            )
        ],
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        ns_hosts=observation,
    )
    missing = next(item for item in report.findings if item.code == "ns_host_nxdomain")
    assert missing.severity == "info"
    assert WEIGHTS["ns_host_nxdomain"] == 0
    assert report.risk.value == 0


def test_ns_host_no_address_is_info_and_unscored() -> None:
    from analyzer.ns import NsHostCheck, evaluate_ns_hosts
    from analyzer.risk import WEIGHTS

    observation = evaluate_ns_hosts(
        "example.com",
        [
            NsHostCheck(
                host="ns1.example.com",
                in_bailiwick=True,
                ipv4=(),
                ipv6=(),
                status="NO ADDRESS",
            )
        ],
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        ns_hosts=observation,
    )
    empty = next(item for item in report.findings if item.code == "ns_host_no_address")
    assert empty.severity == "info"
    assert WEIGHTS["ns_host_no_address"] == 0
    assert report.risk.value == 0


def test_ns_host_resolves_adds_no_points() -> None:
    from analyzer.ns import NsHostCheck, evaluate_ns_hosts

    observation = evaluate_ns_hosts(
        "example.com",
        [
            NsHostCheck(
                host="ns1.example.com",
                in_bailiwick=True,
                ipv4=("192.0.2.53",),
                ipv6=(),
                status="RESOLVES",
            )
        ],
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        ns_hosts=observation,
    )
    assert not any(item.code.startswith("ns_") for item in report.findings)
    assert report.risk.value == 0


def test_cname_target_nxdomain_is_info_and_unscored() -> None:
    from analyzer.cname import CnameTargetCheck, evaluate_cname_targets
    from analyzer.risk import WEIGHTS

    lookup = _lookup(
        cname=[DNSRecord("CNAME", "www.example.com", "gone.example.net", 300)],
        txt=[DNSRecord("TXT", "www.example.com", "v=spf1 -all", 300)],
        caa=[DNSRecord("CAA", "www.example.com", '0 issue "letsencrypt.org"', 3600)],
    )
    observation = evaluate_cname_targets(
        [
            CnameTargetCheck(
                target="gone.example.net",
                chain=("gone.example.net",),
                ipv4=(),
                ipv6=(),
                status="NXDOMAIN",
            )
        ]
    )
    report = SecurityAnalyzer().analyze(
        lookup,
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(lookup.txt),
        evaluate_dmarc("_dmarc.www.example.com", [
            DNSRecord("TXT", "_dmarc.www.example.com", "v=DMARC1; p=reject", 300),
        ]),
        cname_targets=observation,
    )
    missing = next(item for item in report.findings if item.code == "cname_target_nxdomain")
    assert missing.severity == "info"
    assert WEIGHTS["cname_target_nxdomain"] == 0
    assert not any(item.code == "cname_dangling" for item in report.findings)
    assert report.risk.value == 0


def test_cname_target_resolves_skips_legacy_dangling() -> None:
    from analyzer.cname import CnameTargetCheck, evaluate_cname_targets

    lookup = _lookup(
        cname=[DNSRecord("CNAME", "www.example.com", "cdn.example.net", 300)],
        txt=[DNSRecord("TXT", "www.example.com", "v=spf1 -all", 300)],
        caa=[DNSRecord("CAA", "www.example.com", '0 issue "letsencrypt.org"', 3600)],
    )
    observation = evaluate_cname_targets(
        [
            CnameTargetCheck(
                target="cdn.example.net",
                chain=("cdn.example.net",),
                ipv4=("192.0.2.10",),
                ipv6=(),
                status="RESOLVES",
            )
        ]
    )
    report = SecurityAnalyzer().analyze(
        lookup,
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(lookup.txt),
        evaluate_dmarc("_dmarc.www.example.com", [
            DNSRecord("TXT", "_dmarc.www.example.com", "v=DMARC1; p=reject", 300),
        ]),
        cname_targets=observation,
    )
    assert not any(item.code.startswith("cname_") for item in report.findings)
    assert report.risk.value == 0


def test_soa_hidden_primary_is_info_and_unscored() -> None:
    from analyzer.risk import WEIGHTS
    from analyzer.soa import evaluate_soa_ns

    observation = evaluate_soa_ns(
        "example.com",
        "hidden.example.net",
        ("ns1.example.com",),
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        soa_ns=observation,
    )
    hidden = next(item for item in report.findings if item.code == "soa_hidden_primary")
    assert hidden.severity == "info"
    assert WEIGHTS["soa_hidden_primary"] == 0
    assert report.risk.value == 0


def test_soa_ns_aligned_adds_no_points() -> None:
    from analyzer.soa import evaluate_soa_ns

    observation = evaluate_soa_ns(
        "example.com",
        "ns1.example.com",
        ("ns1.example.com", "ns2.example.com"),
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        soa_ns=observation,
    )
    assert not any(item.code.startswith("soa_") for item in report.findings)
    assert report.risk.value == 0


def test_caa_observation_found_adds_no_points() -> None:
    from analyzer.caa import evaluate_caa

    observation = evaluate_caa(
        "example.com",
        [DNSRecord("CAA", "example.com", '0 issue "letsencrypt.org"', 3600)],
    )
    empty = _lookup(
        a=[DNSRecord("A", "example.com", "93.184.216.34", 300)],
        txt=[DNSRecord("TXT", "example.com", "v=spf1 -all", 300)],
    )
    report = SecurityAnalyzer().analyze(
        empty,
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(empty.txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        caa=observation,
    )
    assert not any(item.code.startswith("caa_") for item in report.findings)
    assert report.risk.value == 0


def test_caa_observation_missing_keeps_existing_weight() -> None:
    from analyzer.caa import evaluate_caa
    from analyzer.risk import WEIGHTS

    observation = evaluate_caa("example.com", ())
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        caa=observation,
    )
    missing = next(item for item in report.findings if item.code == "caa_missing")
    assert missing.severity == "info"
    assert WEIGHTS["caa_missing"] == 2


def test_caa_unreadable_is_info_and_unscored() -> None:
    from analyzer.caa import evaluate_caa
    from analyzer.risk import WEIGHTS

    observation = evaluate_caa(
        "example.com", (), error="DNS query timed out."
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(_clean_lookup().txt),
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
        caa=observation,
    )
    unread = next(item for item in report.findings if item.code == "caa_unreadable")
    assert unread.severity == "info"
    assert WEIGHTS["caa_unreadable"] == 0
    assert not any(item.code == "caa_missing" for item in report.findings)
    assert report.risk.value == 0


def test_spf_include_timeout_is_info_not_missing_apex() -> None:
    from analyzer.spf import SpfHop, inspect_spf

    spf = inspect_spf(_clean_lookup().txt)
    spf = replace_hops(
        spf,
        SpfHop(
            kind="include",
            domain="_spf.example.net",
            status="NOT DETECTED",
            policy=None,
            all_term=None,
            all_meaning=None,
            error="DNS query timed out.",
        ),
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        spf,
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
    )
    unread = next(item for item in report.findings if item.code == "spf_include_unreadable")
    assert unread.severity == "info"
    assert not any(item.code == "spf_missing" for item in report.findings)


def test_spf_include_missing_is_low_not_high() -> None:
    from analyzer.spf import SpfHop, inspect_spf

    spf = inspect_spf(_clean_lookup().txt)
    spf = replace_hops(
        spf,
        SpfHop(
            kind="include",
            domain="missing.example.net",
            status="NOT DETECTED",
            policy=None,
            all_term=None,
            all_meaning=None,
        ),
    )
    report = SecurityAnalyzer().analyze(
        _clean_lookup(),
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        spf,
        evaluate_dmarc("_dmarc.example.com", [
            DNSRecord("TXT", "_dmarc.example.com", "v=DMARC1; p=reject", 300),
        ]),
    )
    missing = next(item for item in report.findings if item.code == "spf_include_missing")
    assert missing.severity == "low"
    assert report.highest_severity == "low"


def replace_hops(spf, *hops):
    from dataclasses import replace

    return replace(spf, hops=hops)
