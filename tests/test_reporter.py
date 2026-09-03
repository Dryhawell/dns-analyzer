"""JSON/CSV export tests. No network access."""

import json
from pathlib import Path

from analyzer.dmarc import evaluate_dmarc
from analyzer.dnssec import evaluate_dnssec
from analyzer.models import CoreLookup, DNSRecord
from analyzer.result import DNSAnalysisResult
from analyzer.security import SecurityAnalyzer
from analyzer.spf import inspect_spf
from utils.reporter import (
    SCHEMA,
    dumps_csv,
    dumps_json,
    format_from_suffix,
    result_to_dict,
    suggested_report_path,
    write_csv,
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
    assert payload["target"] == "example.com"
    assert payload["mode"] == "forward"
    assert payload["scan_time"] == "2026-09-03T11:00:00+00:00"
    assert payload["duration_ms"] == 12
    assert payload["records"][0]["value"] == "93.184.216.34"
    assert payload["records"][1]["priority"] == 10
    assert payload["errors"][0]["section"] == "CAA"
    assert payload["dnssec"] is None
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


def test_format_from_suffix() -> None:
    assert format_from_suffix(Path("a.JSON")) == "json"
    assert format_from_suffix(Path("a.csv")) == "csv"
    assert format_from_suffix(Path("a.txt")) is None


def test_suggested_report_path() -> None:
    path = suggested_report_path("example.com", "json", "2026-09-03")
    assert path == Path("reports") / "example_com_2026-09-03.json"


def test_write_report_rejects_unknown_format(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(ValueError, match="Unsupported"):
        write_report(tmp_path / "x.bin", _result(), "pdf")
