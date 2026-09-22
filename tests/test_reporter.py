"""JSON/CSV/HTML export tests. No network access."""

import json
from pathlib import Path

from analyzer.dmarc import evaluate_dmarc
from analyzer.dnssec import DnssecDelegation, DnssecKey, evaluate_dnssec
from analyzer.models import CoreLookup, DNSRecord
from analyzer.result import DNSAnalysisResult
from analyzer.security import SecurityAnalyzer
from analyzer.spf import inspect_spf
from analyzer.version import __version__
from utils.reporter import (
    SCHEMA,
    dumps_csv,
    dumps_html,
    dumps_json,
    format_from_suffix,
    result_to_dict,
    suggested_report_path,
    write_csv,
    write_html,
    write_json,
    write_report,
)


def _result(**overrides) -> DNSAnalysisResult:
    base = DNSAnalysisResult(
        target="example.com",
        mode="forward",
        scan_time="2026-09-03T11:00:00+00:00",
        duration_ms=12,
        records=(
            DNSRecord("A", "example.com", "93.184.216.34", 3600),
            DNSRecord("MX", "example.com", "mail.example.com", 600, priority=10),
        ),
        errors=(("CAA", "DNS query timed out."),),
    )
    return DNSAnalysisResult(**{**base.__dict__, **overrides})


def test_json_contains_required_keys() -> None:
    payload = result_to_dict(_result())
    assert payload["schema"] == SCHEMA
    assert payload["tool_version"] == __version__
    assert payload["target"] == "example.com"
    assert payload["mode"] == "forward"
    assert payload["scan_time"] == "2026-09-03T11:00:00+00:00"
    assert payload["duration_ms"] == 12
    assert payload["records"][0]["value"] == "93.184.216.34"
    assert payload["records"][1]["priority"] == 10
    assert payload["errors"][0]["section"] == "CAA"
    assert payload["dnssec"] is None
    assert payload["dmarc"] is None
    assert payload["mta_sts"] is None
    assert payload["tls_rpt"] is None
    assert payload["bimi"] is None
    assert payload["tlsa"] is None
    assert payload["sshfp"] is None
    assert payload["fcrdns"] is None
    assert payload["mx_hosts"] is None
    assert payload["ns_hosts"] is None
    assert payload["cname_targets"] is None
    assert payload["soa_ns"] is None
    assert payload["caa"] is None
    assert payload["cds"] is None
    assert payload["nsec"] is None
    assert payload["csync"] is None
    assert payload["zonemd"] is None
    assert payload["rrsig"] is None
    assert payload["dkim"] is None
    assert payload["srv"] is None
    assert payload["naptr"] is None
    assert payload["uri"] is None
    assert payload["dname"] is None
    assert payload["ipseckey"] is None
    assert payload["smimea"] is None
    assert payload["security_analysis"] is None
    assert payload["risk_score"] is None


def test_json_includes_security_and_risk() -> None:
    lookup = CoreLookup(
        a=(DNSRecord("A", "example.com", "93.184.216.34", 300),),
        aaaa=(),
        cname=(),
        mx=(),
        ns=(),
        txt=(DNSRecord("TXT", "example.com", "v=spf1 -all", 300),),
        soa=(),
        caa=(DNSRecord("CAA", "example.com", '0 issue "letsencrypt.org"', 3600),),
    )
    security = SecurityAnalyzer().analyze(
        lookup,
        evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        inspect_spf(lookup.txt),
        evaluate_dmarc("_dmarc.example.com", []),
    )
    payload = result_to_dict(
        _result(
            security=security,
            dnssec=evaluate_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
        )
    )
    assert payload["dnssec"]["status"] == "DETECTED"
    assert payload["security_analysis"]["findings"][0]["code"] == "dmarc_missing"
    assert payload["risk_score"]["value"] == 10
    assert payload["risk_score"]["band"] == "LOW"
    assert payload["risk_score"]["contributions"][0]["points"] == 10


def test_json_and_html_include_dnssec_algorithms() -> None:
    observation = evaluate_dnssec(
        dnskey_found=True,
        ds_found=True,
        ad_flag=True,
        keys=(
            DnssecKey(
                flags=257,
                protocol=3,
                algorithm=15,
                algorithm_meaning="Ed25519",
                role="KSK",
                zone_key=True,
                secure_entry_point=True,
                key_tag=12345,
            ),
        ),
        delegations=(
            DnssecDelegation(
                key_tag=12345,
                algorithm=13,
                algorithm_meaning="ECDSAP256SHA256",
                digest_type=2,
                digest_meaning="SHA-256",
            ),
        ),
    )
    payload = result_to_dict(_result(dnssec=observation))
    assert payload["dnssec"]["keys"][0]["algorithm"] == 15
    assert payload["dnssec"]["keys"][0]["algorithm_meaning"] == "Ed25519"
    assert payload["dnssec"]["keys"][0]["role"] == "KSK"
    assert payload["dnssec"]["delegations"][0]["digest_type"] == 2
    page = dumps_html(_result(dnssec=observation))
    assert "Ed25519" in page
    assert "SHA-256" in page
    xss = dumps_html(
        _result(
            dnssec=evaluate_dnssec(
                dnskey_found=True,
                ds_found=True,
                ad_flag=False,
                keys=(
                    DnssecKey(
                        flags=256,
                        protocol=3,
                        algorithm=8,
                        algorithm_meaning="<script>x</script>",
                        role="ZSK",
                        zone_key=True,
                        secure_entry_point=False,
                        key_tag=1,
                    ),
                ),
            )
        )
    )
    assert "<script>x</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_dumps_json_is_parseable() -> None:
    data = json.loads(dumps_json(_result()))
    assert data["target"] == "example.com"


def test_csv_has_header_and_priority() -> None:
    text = dumps_csv(_result())
    lines = text.strip().split("\n")
    assert lines[0] == "record_type,name,value,ttl,priority"
    assert lines[1] == "A,example.com,93.184.216.34,3600,"
    assert lines[2] == "MX,example.com,mail.example.com,600,10"


def test_write_json_and_csv_roundtrip(tmp_path: Path) -> None:
    result = _result()
    json_path = tmp_path / "out.json"
    csv_path = tmp_path / "nested" / "out.csv"
    write_json(json_path, result)
    write_csv(csv_path, result)
    assert json.loads(json_path.read_text(encoding="utf-8"))["target"] == "example.com"
    assert "mail.example.com" in csv_path.read_text(encoding="utf-8")


def test_html_contains_target_and_disclaimer() -> None:
    page = dumps_html(_result())
    assert "<!DOCTYPE html>" in page
    assert "example.com" in page
    assert "not a vulnerability scanner" in page.lower()
    assert "<script" not in page.lower()
    assert "93.184.216.34" in page
    assert "mail.example.com" in page
    assert "DNS query timed out" in page


def test_html_escapes_script_in_txt() -> None:
    page = dumps_html(
        _result(
            records=(
                DNSRecord(
                    "TXT",
                    "example.com",
                    '<script>alert(1)</script>',
                    60,
                ),
            )
        )
    )
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    assert "alert(1)" in page


def test_write_html_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "out.html"
    write_html(path, _result())
    text = path.read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert "example.com" in text


def test_format_from_suffix() -> None:
    assert format_from_suffix(Path("a.JSON")) == "json"
    assert format_from_suffix(Path("a.csv")) == "csv"
    assert format_from_suffix(Path("a.HTML")) == "html"
    assert format_from_suffix(Path("a.txt")) is None


def test_suggested_report_path() -> None:
    path = suggested_report_path("example.com", "json", "2026-09-03")
    assert path == Path("reports") / "example_com_2026-09-03.json"


def test_write_report_rejects_unknown_format(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(ValueError, match="Unsupported"):
        write_report(tmp_path / "x.bin", _result(), "pdf")


def test_json_and_html_include_dkim() -> None:
    from analyzer.dkim import evaluate_dkim

    observation = evaluate_dkim(
        "google._domainkey.example.com",
        "google",
        [DNSRecord("TXT", "google._domainkey.example.com", "v=DKIM1; p=MIIB", 300)],
    )
    result = _result(dkim=(observation,))
    payload = result_to_dict(result)
    assert payload["dkim"][0]["selector"] == "google"
    assert payload["dkim"][0]["status"] == "FOUND"
    assert payload["dkim"][0]["key_present"] is True
    page = dumps_html(result)
    assert "google._domainkey.example.com" in page
    assert "FOUND" in page


def test_json_and_html_include_srv() -> None:
    from analyzer.srv import SrvSpec, evaluate_srv

    observation = evaluate_srv(
        "_sip._tcp.example.com",
        SrvSpec("sip", "tcp"),
        [
            DNSRecord(
                "SRV",
                "_sip._tcp.example.com",
                "10 5 5060 sip.example.com",
                300,
                priority=10,
            )
        ],
    )
    result = _result(srv=(observation,))
    payload = result_to_dict(result)
    assert payload["srv"][0]["service"] == "sip"
    assert payload["srv"][0]["protocol"] == "tcp"
    assert payload["srv"][0]["status"] == "FOUND"
    assert payload["srv"][0]["records"][0]["value"] == "10 5 5060 sip.example.com"
    page = dumps_html(result)
    assert "_sip._tcp.example.com" in page
    assert "sip.example.com" in page
    xss = dumps_html(
        _result(
            srv=(
                evaluate_srv(
                    "_x._tcp.example.com",
                    SrvSpec("x", "tcp"),
                    [
                        DNSRecord(
                            "SRV",
                            "_x._tcp.example.com",
                            '<script>alert(1)</script>',
                            60,
                            priority=0,
                        )
                    ],
                ),
            )
        )
    )
    assert "<script>alert(1)</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_naptr() -> None:
    from analyzer.naptr import evaluate_naptr

    observation = evaluate_naptr(
        "example.com",
        [
            DNSRecord(
                "NAPTR",
                "example.com",
                '100 50 "u" "E2U+sip" "!^.*$!sip:info@example.com!" .',
                300,
            )
        ],
    )
    result = _result(naptr=observation)
    payload = result_to_dict(result)
    assert payload["naptr"]["status"] == "FOUND"
    assert payload["naptr"]["rewrites"][0]["services"] == "E2U+sip"
    assert payload["naptr"]["rewrites"][0]["order"] == 100
    page = dumps_html(result)
    assert "E2U+sip" in page
    assert "sip:info@example.com" in page
    xss = dumps_html(
        _result(
            naptr=evaluate_naptr(
                "example.com",
                [
                    DNSRecord(
                        "NAPTR",
                        "example.com",
                        '10 10 "u" "E2U+sip" "!^.*$!<script>alert(1)</script>!" .',
                        60,
                    )
                ],
            )
        )
    )
    assert "<script>alert(1)</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_uri() -> None:
    from analyzer.uri import evaluate_uri

    observation = evaluate_uri(
        "example.com",
        [
            DNSRecord(
                "URI",
                "example.com",
                '10 1 "https://www.example.com/path"',
                300,
            )
        ],
    )
    result = _result(uri=observation)
    payload = result_to_dict(result)
    assert payload["uri"]["status"] == "FOUND"
    assert payload["uri"]["uris"][0]["scheme"] == "https"
    assert payload["uri"]["uris"][0]["priority"] == 10
    page = dumps_html(result)
    assert "https://www.example.com/path" in page
    assert "https" in page
    xss = dumps_html(
        _result(
            uri=evaluate_uri(
                "example.com",
                [
                    DNSRecord(
                        "URI",
                        "example.com",
                        '10 1 "https://example.com/<script>alert(1)</script>"',
                        60,
                    )
                ],
            )
        )
    )
    assert "<script>alert(1)</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_dname() -> None:
    from analyzer.dname import evaluate_dname

    observation = evaluate_dname(
        "example.com",
        [
            DNSRecord(
                "DNAME",
                "example.com",
                "other.example.net",
                300,
            )
        ],
    )
    result = _result(dname=observation)
    payload = result_to_dict(result)
    assert payload["dname"]["status"] == "FOUND"
    assert payload["dname"]["dnames"][0]["target"] == "other.example.net"
    page = dumps_html(result)
    assert "other.example.net" in page
    xss = dumps_html(
        _result(
            dname=evaluate_dname(
                "example.com",
                [
                    DNSRecord(
                        "DNAME",
                        "example.com",
                        "<script>alert(1)</script>",
                        60,
                    )
                ],
            )
        )
    )
    assert "<script>alert(1)</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_ipseckey() -> None:
    from analyzer.ipseckey import evaluate_ipseckey

    observation = evaluate_ipseckey(
        "example.com",
        [
            DNSRecord(
                "IPSECKEY",
                "example.com",
                "10 1 2 192.0.2.1 key-length=64",
                300,
            )
        ],
    )
    result = _result(ipseckey=observation)
    payload = result_to_dict(result)
    assert payload["ipseckey"]["status"] == "FOUND"
    assert payload["ipseckey"]["ipseckeys"][0]["gateway"] == "192.0.2.1"
    assert payload["ipseckey"]["ipseckeys"][0]["key_length"] == 64
    page = dumps_html(result)
    assert "192.0.2.1" in page
    assert "IPSECKEY" in page
    xss = dumps_html(
        _result(
            ipseckey=evaluate_ipseckey(
                "example.com",
                [
                    DNSRecord(
                        "IPSECKEY",
                        "example.com",
                        "10 3 2 <script>alert(1)</script> key-length=8",
                        60,
                    )
                ],
            )
        )
    )
    assert "<script>alert(1)</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_smimea() -> None:
    from analyzer.smimea import evaluate_smimea, smimea_query_name

    qname = smimea_query_name("example.com", "alice")
    observation = evaluate_smimea(
        qname,
        "alice",
        [DNSRecord("SMIMEA", qname, "3 1 1 assoc-length=32", 300)],
    )
    result = _result(smimea=(observation,))
    payload = result_to_dict(result)
    assert payload["smimea"][0]["status"] == "FOUND"
    assert payload["smimea"][0]["local_part"] == "alice"
    assert payload["smimea"][0]["associations"][0]["association_length"] == 32
    page = dumps_html(result)
    assert "alice" in page
    assert "SMIMEA" in page
    xss = dumps_html(
        _result(
            smimea=(
                evaluate_smimea(
                    qname,
                    "<script>alert(1)</script>",
                    [DNSRecord("SMIMEA", qname, "3 1 1 assoc-length=8", 60)],
                ),
            )
        )
    )
    assert "<script>alert(1)</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_cds() -> None:
    from analyzer.cds import CdnskeyRecord, CdsRecord, evaluate_cds

    observation = evaluate_cds(
        "example.com",
        cds_found=True,
        cdnskey_found=True,
        cds=(
            CdsRecord(
                key_tag=2371,
                algorithm=13,
                algorithm_meaning="ECDSAP256SHA256",
                digest_type=2,
                digest_meaning="SHA-256",
            ),
        ),
        cdnskey=(
            CdnskeyRecord(
                flags=257,
                protocol=3,
                algorithm=13,
                algorithm_meaning="ECDSAP256SHA256",
                role="KSK",
                zone_key=True,
                secure_entry_point=True,
                key_tag=2371,
            ),
        ),
    )
    result = _result(cds=observation)
    payload = result_to_dict(result)
    assert payload["cds"]["status"] == "FOUND"
    assert payload["cds"]["cds"][0]["digest_type"] == 2
    assert payload["cds"]["cdnskey"][0]["algorithm"] == 13
    page = dumps_html(result)
    assert "SHA-256" in page
    assert "CDNSKEY" in page
    xss = dumps_html(
        _result(
            cds=evaluate_cds(
                "example.com",
                cds_found=True,
                cdnskey_found=False,
                cds=(
                    CdsRecord(
                        key_tag=1,
                        algorithm=8,
                        algorithm_meaning="<script>x</script>",
                        digest_type=2,
                        digest_meaning="SHA-256",
                    ),
                ),
            )
        )
    )
    assert "<script>x</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_nsec() -> None:
    from analyzer.nsec import Nsec3ParamRecord, NsecRecord, evaluate_nsec

    observation = evaluate_nsec(
        "example.com",
        nsec_found=True,
        nsec3param_found=True,
        nsec=(
            NsecRecord(
                next_name="www.<script>alert(1)</script>.example.com",
                types=("A", "NS", "SOA"),
            ),
        ),
        nsec3param=(
            Nsec3ParamRecord(
                algorithm=1,
                algorithm_meaning="SHA-1 (NSEC3 hash)",
                flags=0,
                opt_out=False,
                iterations=0,
                salt_length=4,
                iterations_note="0 iterations (RFC 9276)",
            ),
        ),
    )
    result = _result(nsec=observation)
    payload = result_to_dict(result)
    assert payload["nsec"]["status"] == "FOUND"
    assert payload["nsec"]["nsec"][0]["next_name"] == "www.<script>alert(1)</script>.example.com"
    assert payload["nsec"]["nsec3param"][0]["salt_length"] == 4
    page = dumps_html(result)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    assert "NSEC3PARAM" in page
    assert "salt length 4" in page


def test_json_and_html_include_csync() -> None:
    from analyzer.csync import CsyncRecord, evaluate_csync

    observation = evaluate_csync(
        "example.com",
        found=True,
        csync=(
            CsyncRecord(
                serial=2026091501,
                flags=1,
                immediate=True,
                soa_minimum=False,
                types=("NS", "A"),
            ),
        ),
    )
    result = _result(csync=observation)
    payload = result_to_dict(result)
    assert payload["csync"]["status"] == "FOUND"
    assert payload["csync"]["csync"][0]["serial"] == 2026091501
    assert payload["csync"]["csync"][0]["types"] == ["NS", "A"]
    page = dumps_html(result)
    assert "2026091501" in page
    assert "immediate" in page
    xss = dumps_html(
        _result(
            csync=evaluate_csync(
                "example.com",
                found=True,
                csync=(
                    CsyncRecord(
                        serial=1,
                        flags=0,
                        immediate=False,
                        soa_minimum=False,
                        types=("<script>x</script>",),
                    ),
                ),
            )
        )
    )
    assert "<script>x</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_zonemd() -> None:
    from analyzer.zonemd import ZonemdRecord, evaluate_zonemd

    observation = evaluate_zonemd(
        "example.com",
        found=True,
        zonemd=(
            ZonemdRecord(
                serial=2026091601,
                scheme=1,
                scheme_meaning="SIMPLE",
                hash_algorithm=1,
                hash_meaning="SHA-384",
                digest_length=48,
            ),
        ),
    )
    result = _result(zonemd=observation)
    payload = result_to_dict(result)
    assert payload["zonemd"]["status"] == "FOUND"
    assert payload["zonemd"]["zonemd"][0]["serial"] == 2026091601
    assert payload["zonemd"]["zonemd"][0]["digest_length"] == 48
    page = dumps_html(result)
    assert "SHA-384" in page
    assert "digest length 48" in page
    xss = dumps_html(
        _result(
            zonemd=evaluate_zonemd(
                "example.com",
                found=True,
                zonemd=(
                    ZonemdRecord(
                        serial=1,
                        scheme=1,
                        scheme_meaning="<script>x</script>",
                        hash_algorithm=1,
                        hash_meaning="SHA-384",
                        digest_length=48,
                    ),
                ),
            )
        )
    )
    assert "<script>x</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_rrsig() -> None:
    from analyzer.rrsig import RrsigRecord, evaluate_rrsig

    observation = evaluate_rrsig(
        "example.com",
        found=True,
        rrsig=(
            RrsigRecord(
                type_covered=1,
                type_covered_name="A",
                algorithm=13,
                algorithm_meaning="ECDSAP256SHA256",
                labels=2,
                original_ttl=300,
                inception=1758240000,
                expiration=1760918400,
                inception_utc="2025-09-19T00:00:00Z",
                expiration_utc="2025-10-20T00:00:00Z",
                key_tag=2371,
                signer="example.com",
                signature_length=64,
            ),
        ),
    )
    result = _result(rrsig=observation)
    payload = result_to_dict(result)
    assert payload["rrsig"]["status"] == "FOUND"
    assert payload["rrsig"]["rrsig"][0]["type_covered_name"] == "A"
    assert payload["rrsig"]["rrsig"][0]["key_tag"] == 2371
    assert payload["rrsig"]["rrsig"][0]["signature_length"] == 64
    page = dumps_html(result)
    assert "ECDSAP256SHA256" in page
    assert "sig length 64" in page
    xss = dumps_html(
        _result(
            rrsig=evaluate_rrsig(
                "example.com",
                found=True,
                rrsig=(
                    RrsigRecord(
                        type_covered=1,
                        type_covered_name="A",
                        algorithm=13,
                        algorithm_meaning="<script>x</script>",
                        labels=2,
                        original_ttl=300,
                        inception=1758240000,
                        expiration=1760918400,
                        inception_utc="2025-09-19T00:00:00Z",
                        expiration_utc="2025-10-20T00:00:00Z",
                        key_tag=2371,
                        signer="example.com",
                        signature_length=64,
                    ),
                ),
            )
        )
    )
    assert "<script>x</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_mta_sts() -> None:
    from analyzer.mtasts import evaluate_mta_sts

    observation = evaluate_mta_sts(
        "_mta-sts.example.com",
        "mta-sts.example.com",
        [DNSRecord("TXT", "_mta-sts.example.com", "v=STSv1; id=20160831085700Z", 300)],
    )
    result = _result(mta_sts=observation)
    payload = result_to_dict(result)
    assert payload["mta_sts"]["status"] == "FOUND"
    assert payload["mta_sts"]["id"] == "20160831085700Z"
    assert payload["mta_sts"]["policy_host"] == "mta-sts.example.com"
    page = dumps_html(result)
    assert "_mta-sts.example.com" in page
    assert "20160831085700Z" in page
    xss = dumps_html(
        _result(
            mta_sts=evaluate_mta_sts(
                "_mta-sts.example.com",
                "mta-sts.example.com",
                [DNSRecord("TXT", "_mta-sts.example.com", 'v=STSv1; id=<script>x</script>', 300)],
            )
        )
    )
    assert "<script>x</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_tls_rpt() -> None:
    from analyzer.tlsrpt import evaluate_tls_rpt

    observation = evaluate_tls_rpt(
        "_smtp._tls.example.com",
        [DNSRecord("TXT", "_smtp._tls.example.com", "v=TLSRPTv1; rua=mailto:tlsrpt@example.com", 300)],
    )
    result = _result(tls_rpt=observation)
    payload = result_to_dict(result)
    assert payload["tls_rpt"]["status"] == "FOUND"
    assert payload["tls_rpt"]["rua"] == "mailto:tlsrpt@example.com"
    page = dumps_html(result)
    assert "_smtp._tls.example.com" in page
    assert "mailto:tlsrpt@example.com" in page
    xss = dumps_html(
        _result(
            tls_rpt=evaluate_tls_rpt(
                "_smtp._tls.example.com",
                [DNSRecord("TXT", "_smtp._tls.example.com", "v=TLSRPTv1; rua=<script>x</script>", 300)],
            )
        )
    )
    assert "<script>x</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_bimi() -> None:
    from analyzer.bimi import evaluate_bimi

    observation = evaluate_bimi(
        "default._bimi.example.com",
        "default",
        [DNSRecord("TXT", "default._bimi.example.com", "v=BIMI1; l=https://example.com/logo.svg", 300)],
    )
    result = _result(bimi=observation)
    payload = result_to_dict(result)
    assert payload["bimi"]["status"] == "FOUND"
    assert payload["bimi"]["selector"] == "default"
    assert payload["bimi"]["location"] == "https://example.com/logo.svg"
    page = dumps_html(result)
    assert "default._bimi.example.com" in page
    assert "https://example.com/logo.svg" in page
    xss = dumps_html(
        _result(
            bimi=evaluate_bimi(
                "default._bimi.example.com",
                "default",
                [DNSRecord("TXT", "default._bimi.example.com", "v=BIMI1; l=<script>x</script>", 300)],
            )
        )
    )
    assert "<script>x</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_tlsa() -> None:
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
    result = _result(tlsa=observation)
    payload = result_to_dict(result)
    assert payload["tlsa"]["status"] == "FOUND"
    assert payload["tlsa"]["query_name"] == "_443._tcp.example.com"
    assert payload["tlsa"]["records"][0]["usage"] == 3
    page = dumps_html(result)
    assert "_443._tcp.example.com" in page
    assert "DANE-EE" in page
    xss = dumps_html(
        _result(
            tlsa=evaluate_tlsa(
                "_443._tcp.example.com",
                [
                    DNSRecord(
                        "TLSA",
                        "_443._tcp.example.com",
                        "3 1 1 <script>x</script>",
                        300,
                        details=(
                            ("Usage", "3 — DANE-EE"),
                            ("Selector", "1 — SPKI"),
                            ("Matching", "1 — SHA-256"),
                            ("Association", "<script>x</script>"),
                        ),
                    )
                ],
            )
        )
    )
    assert "<script>x</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_sshfp() -> None:
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
    result = _result(sshfp=observation)
    payload = result_to_dict(result)
    assert payload["sshfp"]["status"] == "FOUND"
    assert payload["sshfp"]["records"][0]["algorithm"] == 4
    page = dumps_html(result)
    assert "SSHFP" in page
    assert "Ed25519" in page
    xss = dumps_html(
        _result(
            sshfp=evaluate_sshfp(
                "example.com",
                [
                    DNSRecord(
                        "SSHFP",
                        "example.com",
                        "4 2 <script>x</script>",
                        300,
                        details=(
                            ("Algorithm", "4 — Ed25519"),
                            ("Fingerprint type", "2 — SHA-256"),
                            ("Fingerprint", "<script>x</script>"),
                        ),
                    )
                ],
            )
        )
    )
    assert "<script>x</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_fcrdns() -> None:
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
    result = _result(fcrdns=observation)
    payload = result_to_dict(result)
    assert payload["fcrdns"]["checks"][0]["status"] == "CONFIRMED"
    page = dumps_html(result)
    assert "FCrDNS" in page
    assert "CONFIRMED" in page
    xss = dumps_html(
        _result(
            fcrdns=evaluate_fcrdns(
                [
                    FcrdnsCheck(
                        ip="93.184.216.34",
                        ptr_query="34.216.184.93.in-addr.arpa",
                        ptr_names=("<script>x</script>",),
                        forward_ips=(),
                        status="NO PTR",
                    )
                ]
            )
        )
    )
    assert "<script>x</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_mx_hosts() -> None:
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
    result = _result(mx_hosts=observation)
    payload = result_to_dict(result)
    assert payload["mx_hosts"]["status"] == "FOUND"
    assert payload["mx_hosts"]["checks"][0]["host"] == "mail.example.com"
    page = dumps_html(result)
    assert "MX hosts" in page
    assert "RESOLVES" in page
    xss = dumps_html(
        _result(
            mx_hosts=evaluate_mx_hosts(
                "example.com",
                [
                    MxHostCheck(
                        host="<script>x</script>",
                        preference=10,
                        ipv4=(),
                        ipv6=(),
                        status="NXDOMAIN",
                    )
                ],
            )
        )
    )
    assert "<script>x</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_ns_hosts() -> None:
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
    result = _result(ns_hosts=observation)
    payload = result_to_dict(result)
    assert payload["ns_hosts"]["status"] == "FOUND"
    assert payload["ns_hosts"]["checks"][0]["in_bailiwick"] is True
    page = dumps_html(result)
    assert "NS hosts" in page
    assert "in-bailiwick" in page
    xss = dumps_html(
        _result(
            ns_hosts=evaluate_ns_hosts(
                "example.com",
                [
                    NsHostCheck(
                        host="<script>x</script>",
                        in_bailiwick=False,
                        ipv4=(),
                        ipv6=(),
                        status="NXDOMAIN",
                    )
                ],
            )
        )
    )
    assert "<script>x</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_cname_targets() -> None:
    from analyzer.cname import CnameTargetCheck, evaluate_cname_targets

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
    result = _result(cname_targets=observation)
    payload = result_to_dict(result)
    assert payload["cname_targets"]["status"] == "FOUND"
    assert payload["cname_targets"]["checks"][0]["target"] == "cdn.example.net"
    page = dumps_html(result)
    assert "CNAME targets" in page
    assert "RESOLVES" in page
    xss = dumps_html(
        _result(
            cname_targets=evaluate_cname_targets(
                [
                    CnameTargetCheck(
                        target="<script>x</script>",
                        chain=("<script>x</script>",),
                        ipv4=(),
                        ipv6=(),
                        status="NXDOMAIN",
                    )
                ]
            )
        )
    )
    assert "<script>x</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_soa_ns() -> None:
    from analyzer.soa import evaluate_soa_ns

    observation = evaluate_soa_ns(
        "example.com",
        "ns1.example.com",
        ("ns1.example.com", "ns2.example.com"),
        serial="2026091301",
    )
    result = _result(soa_ns=observation)
    payload = result_to_dict(result)
    assert payload["soa_ns"]["status"] == "ALIGNED"
    assert payload["soa_ns"]["mname"] == "ns1.example.com"
    page = dumps_html(result)
    assert "SOA / NS" in page
    assert "ALIGNED" in page
    xss = dumps_html(
        _result(
            soa_ns=evaluate_soa_ns(
                "example.com",
                "<script>x</script>",
                ("ns1.example.com",),
            )
        )
    )
    assert "<script>x</script>" not in xss
    assert "&lt;script&gt;" in xss


def test_json_and_html_include_caa_summary() -> None:
    from analyzer.caa import evaluate_caa

    observation = evaluate_caa(
        "example.com",
        [
            DNSRecord("CAA", "example.com", '0 issue "letsencrypt.org"', 3600),
            DNSRecord("CAA", "example.com", '0 issuewild "letsencrypt.org"', 3600),
            DNSRecord("CAA", "example.com", '0 iodef "mailto:caa@example.com"', 3600),
        ],
    )
    result = _result(caa=observation)
    payload = result_to_dict(result)
    assert payload["caa"]["status"] == "FOUND"
    assert payload["caa"]["issue"] == ["letsencrypt.org"]
    assert payload["caa"]["issuewild"] == ["letsencrypt.org"]
    assert payload["caa"]["iodef"] == ["mailto:caa@example.com"]
    page = dumps_html(result)
    assert "letsencrypt.org" in page
    assert "mailto:caa@example.com" in page
    xss = dumps_html(
        _result(
            caa=evaluate_caa(
                "example.com",
                [DNSRecord("CAA", "example.com", '0 issue "<script>x</script>"', 3600)],
            )
        )
    )
    assert "<script>x</script>" not in xss
    assert "&lt;script&gt;" in xss
