"""JSON/CSV/HTML export tests. No network access."""

import json
from pathlib import Path

from analyzer.dmarc import evaluate_dmarc
from analyzer.dnssec import evaluate_dnssec
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
    assert payload["dkim"] is None
    assert payload["srv"] is None
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
