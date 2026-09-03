"""CLI tests with a mocked resolver. No network access."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from analyzer.dmarc import evaluate_dmarc
from analyzer.dnssec import evaluate_dnssec
from analyzer.exceptions import DNSTimeoutError, DomainNotFoundError
from analyzer.models import CoreLookup, DNSRecord
from cli.interface import ExportPlan, build_parser, plan_export, run


def _lookup(
    a: list[DNSRecord] | None = None,
    aaaa: list[DNSRecord] | None = None,
    cname: list[DNSRecord] | None = None,
    mx: list[DNSRecord] | None = None,
    ns: list[DNSRecord] | None = None,
    txt: list[DNSRecord] | None = None,
    soa: list[DNSRecord] | None = None,
    caa: list[DNSRecord] | None = None,
    errors: tuple[tuple[str, str], ...] = (),
) -> CoreLookup:
    return CoreLookup(
        a=tuple(a or []),
        aaaa=tuple(aaaa or []),
        cname=tuple(cname or []),
        mx=tuple(mx or []),
        ns=tuple(ns or []),
        txt=tuple(txt or []),
        soa=tuple(soa or []),
        caa=tuple(caa or []),
        errors=errors,
    )


def _dnssec(
    dnskey_found: bool = False,
    ds_found: bool = False,
    ad_flag: bool = False,
):
    return evaluate_dnssec(
        dnskey_found=dnskey_found,
        ds_found=ds_found,
        ad_flag=ad_flag,
    )


def _dmarc(record: str | None = None) -> object:
    qname = "_dmarc.example.com"
    if record is None:
        return evaluate_dmarc(qname, ())
    return evaluate_dmarc(qname, [DNSRecord("TXT", qname, record, 300)])


def _bind(mock_cls, lookup: CoreLookup, dnssec=None, dmarc=None) -> None:
    mock_cls.return_value.lookup_core.return_value = lookup
    mock_cls.return_value.inspect_dnssec.return_value = dnssec or _dnssec()
    mock_cls.return_value.inspect_dmarc.return_value = dmarc or _dmarc()


@patch("cli.interface.DNSResolver")
def test_cli_prints_a_and_aaaa(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            a=[DNSRecord("A", "example.com", "93.184.216.34", 3600)],
            aaaa=[DNSRecord("AAAA", "example.com", "2001:db8::1", 300)],
        ),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "Target:" in output
    assert "example.com" in output
    assert "A RECORDS" in output
    assert "93.184.216.34" in output
    assert "TTL: 3600s (1h)" in output
    assert "AAAA RECORDS" in output
    assert "2001:db8::1" in output
    assert "TTL: 300s (5m)" in output
    assert "TTL SUMMARY" in output
    assert "not a security score" in output
    assert "remaining TTL" in output


@patch("cli.interface.DNSResolver")
def test_cli_missing_aaaa_is_not_an_error(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 3600)]),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "No AAAA record found." in output


@patch("cli.interface.DNSResolver")
def test_cli_notes_private_scope(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "intranet.example", "10.0.0.5", 60)]),
    )

    assert run(["intranet.example"]) == 0
    assert "Scope: private" in capsys.readouterr().out


@patch("cli.interface.DNSResolver")
def test_cli_prints_cname_mx_ns(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            cname=[DNSRecord("CNAME", "www.example.com", "example.com", 600)],
            mx=[
                DNSRecord("MX", "example.com", "mail-b.example.com", 3600, priority=20),
                DNSRecord("MX", "example.com", "mail-a.example.com", 3600, priority=10),
            ],
            ns=[
                DNSRecord("NS", "example.com", "ns2.example.com", 86400),
                DNSRecord("NS", "example.com", "ns1.example.com", 86400),
            ],
        ),
    )

    assert run(["www.example.com"]) == 0
    output = capsys.readouterr().out
    assert "www.example.com → example.com" in output
    assert "mail-a.example.com" in output
    assert output.find("mail-a.example.com") < output.find("mail-b.example.com")
    assert "Priority: 10" in output
    assert "Priority: 20" in output
    assert output.find("ns1.example.com") < output.find("ns2.example.com")


@patch("cli.interface.DNSResolver")
def test_cli_prints_txt_soa_caa(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            txt=[DNSRecord("TXT", "example.com", "v=spf1 -all", 300)],
            soa=[
                DNSRecord(
                    "SOA",
                    "example.com",
                    "ns1.example.com serial=2026090201",
                    60,
                    details=(
                        ("Primary NS", "ns1.example.com"),
                        ("Mailbox", "hostmaster.example.com"),
                        ("Serial", "2026090201"),
                    ),
                )
            ],
            caa=[
                DNSRecord(
                    "CAA",
                    "example.com",
                    '0 issue "letsencrypt.org"',
                    3600,
                    details=(("Tag", "issue — allows this CA to issue certificates"),),
                )
            ],
        ),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert '"v=spf1 -all"' in output
    assert "Primary NS: ns1.example.com" in output
    assert "Serial: 2026090201" in output
    assert '0 issue "letsencrypt.org"' in output
    assert "No CAA record found." not in output
    assert "SPF" in output
    assert "Status: FOUND" in output
    assert "v=spf1 -all" in output


@patch("cli.interface.DNSResolver")
def test_cli_shows_section_timeout_not_empty(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            a=[DNSRecord("A", "example.com", "93.184.216.34", 60)],
            errors=(("CAA", "DNS query timed out."),),
        ),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "93.184.216.34" in output
    assert "Error: DNS query timed out." in output
    assert "No CAA record found." not in output


@patch("cli.interface.DNSResolver")
def test_cli_reverse_prints_ptr(mock_resolver_cls, capsys) -> None:
    mock_resolver_cls.return_value.resolve_reverse.return_value = [
        DNSRecord("PTR", "8.8.8.8.in-addr.arpa", "dns.google", 86400),
    ]

    assert run(["--reverse", "8.8.8.8"]) == 0
    output = capsys.readouterr().out
    assert "REVERSE DNS" in output
    assert "8.8.8.8" in output
    assert "→ dns.google" in output
    assert "8.8.8.8.in-addr.arpa" in output


@patch("cli.interface.DNSResolver")
def test_cli_reverse_missing_ptr(mock_resolver_cls, capsys) -> None:
    mock_resolver_cls.return_value.resolve_reverse.return_value = []

    assert run(["--reverse", "203.0.113.1"]) == 0
    assert "No PTR record found." in capsys.readouterr().out


def test_cli_positional_ip_hints_reverse(capsys) -> None:
    assert run(["8.8.8.8"]) == 1
    assert "--reverse" in capsys.readouterr().err


@patch("cli.interface.DNSResolver")
def test_cli_prints_dnssec_detected(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        dnssec=_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "DNSSEC" in output
    assert "Status: DETECTED" in output
    assert "DNSKEY: FOUND" in output
    assert "DS:     FOUND" in output
    assert "AD flag: SET" in output
    assert "does not mean the domain is compromised" in output
    assert "strip DNSKEY" in output


@patch("cli.interface.DNSResolver")
def test_cli_prints_dmarc_reject(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        dmarc=_dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@example.com"),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "DMARC" in output
    assert "Status: FOUND" in output
    assert "p=reject" in output
    assert "_dmarc.example.com" in output
    assert "does not mean the domain is compromised" in output


@patch("cli.interface.DNSResolver")
def test_cli_prints_security_observations(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "SECURITY ANALYSIS" in output
    assert "[LOW] SPF not published" in output
    assert "[LOW] DMARC not published" in output
    assert "[HIGH]" not in output
    assert "not vulnerability scanner results" in output
    assert "RISK SCORE" in output
    assert "Band:" in output
    assert "not CVSS" in output
    assert "Contributions:" in output
    assert "+10  DMARC not published" in output
    assert "+5  DNSSEC not detected by this resolver" in output


@patch("cli.interface.DNSResolver")
def test_cli_security_flags_private_address(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "intranet.example", "10.0.0.5", 60)]),
    )

    assert run(["intranet.example"]) == 0
    output = capsys.readouterr().out
    assert "[MEDIUM] A points to a private address" in output
    assert "Scope: private" in output


@patch("cli.interface.DNSResolver")
def test_cli_record_filter_hides_other_sections(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            a=[DNSRecord("A", "example.com", "93.184.216.34", 3600)],
            mx=[DNSRecord("MX", "example.com", "mail.example.com", 3600, priority=10)],
        ),
    )

    assert run(["example.com", "--record", "a"]) == 0
    output = capsys.readouterr().out
    assert "A RECORDS" in output
    assert "93.184.216.34" in output
    assert "MX RECORDS" not in output
    assert "mail.example.com" not in output
    assert "SECURITY ANALYSIS" not in output
    assert "RISK SCORE" not in output
    mock_resolver_cls.return_value.inspect_dnssec.assert_not_called()
    mock_resolver_cls.return_value.inspect_dmarc.assert_not_called()


@patch("cli.interface.DNSResolver")
def test_cli_record_can_be_repeated(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            a=[DNSRecord("A", "example.com", "93.184.216.34", 60)],
            mx=[DNSRecord("MX", "example.com", "mail.example.com", 60, priority=10)],
            ns=[DNSRecord("NS", "example.com", "ns1.example.com", 86400)],
        ),
    )

    assert run(["example.com", "--record", "MX", "--record", "NS"]) == 0
    output = capsys.readouterr().out
    assert "MX RECORDS" in output
    assert "NS RECORDS" in output
    assert "A RECORDS" not in output
    assert "SECURITY ANALYSIS" not in output


@patch("cli.interface.DNSResolver")
def test_cli_security_flag_skips_record_dump(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )

    assert run(["example.com", "--security"]) == 0
    output = capsys.readouterr().out
    assert "A RECORDS" not in output
    assert "TTL SUMMARY" not in output
    assert "DNSSEC" in output
    assert "SPF" in output
    assert "DMARC" in output
    assert "SECURITY ANALYSIS" in output
    assert "RISK SCORE" in output
    mock_resolver_cls.return_value.inspect_dnssec.assert_called_once()


@patch("cli.interface.DNSResolver")
def test_cli_record_plus_security(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            a=[DNSRecord("A", "example.com", "93.184.216.34", 60)],
            mx=[DNSRecord("MX", "example.com", "mail.example.com", 60, priority=10)],
        ),
    )

    assert run(["example.com", "--record", "A", "--security"]) == 0
    output = capsys.readouterr().out
    assert "A RECORDS" in output
    assert "MX RECORDS" not in output
    assert "SECURITY ANALYSIS" in output


@patch("cli.interface.DNSResolver")
def test_cli_all_flag_is_full_report(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )

    assert run(["example.com", "--all"]) == 0
    output = capsys.readouterr().out
    assert "A RECORDS" in output
    assert "SECURITY ANALYSIS" in output
    assert "RISK SCORE" in output


def test_cli_rejects_unknown_record_type(capsys) -> None:
    assert run(["example.com", "--record", "FOO"]) == 1
    assert "Unknown record type" in capsys.readouterr().err


def test_cli_record_ptr_hints_reverse(capsys) -> None:
    assert run(["example.com", "--record", "PTR"]) == 1
    assert "--reverse" in capsys.readouterr().err


def test_cli_rejects_all_with_record(capsys) -> None:
    assert run(["example.com", "--all", "--record", "A"]) == 1
    assert "Do not combine --all" in capsys.readouterr().err


def test_cli_rejects_reverse_with_security(capsys) -> None:
    assert run(["--reverse", "8.8.8.8", "--security"]) == 1
    assert "--reverse" in capsys.readouterr().err


def test_cli_help_lists_modes() -> None:
    help_text = build_parser().format_help()
    assert "--record" in help_text
    assert "--security" in help_text
    assert "--all" in help_text
    assert "--reverse" in help_text
    assert "--format" in help_text
    assert "--output" in help_text
    assert "not a vulnerability scanner" in help_text.lower()


def test_cli_help_exit_zero() -> None:
    with pytest.raises(SystemExit) as caught:
        run(["--help"])
    assert caught.value.code == 0


@patch("cli.interface.DNSResolver")
def test_cli_format_json_stdout(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )

    assert run(["example.com", "--format", "json"]) == 0
    captured = capsys.readouterr()
    assert "DNS ANALYZER" not in captured.out
    data = json.loads(captured.out)
    assert data["schema"] == "dns-analyzer.report.v1"
    assert data["target"] == "example.com"
    assert data["mode"] == "forward"
    assert data["records"][0]["value"] == "93.184.216.34"
    assert data["risk_score"]["band"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert data["security_analysis"]["findings"]


@patch("cli.interface.DNSResolver")
def test_cli_format_csv_stdout(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            a=[DNSRecord("A", "example.com", "93.184.216.34", 60)],
            mx=[DNSRecord("MX", "example.com", "mail.example.com", 300, priority=10)],
        ),
    )

    assert run(["example.com", "--format", "csv", "--record", "A"]) == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("record_type,name,value,ttl,priority")
    assert "93.184.216.34" in captured.out
    assert "mail.example.com" in captured.out
    assert "DNS ANALYZER" not in captured.out
    mock_resolver_cls.return_value.inspect_dnssec.assert_not_called()


@patch("cli.interface.DNSResolver")
def test_cli_output_json_file_keeps_human(mock_resolver_cls, tmp_path: Path, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    path = tmp_path / "example.json"

    assert run(["example.com", "--output", str(path)]) == 0
    captured = capsys.readouterr()
    assert "DNS ANALYZER" in captured.out
    assert f"Wrote {path}" in captured.err
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["target"] == "example.com"
    assert data["records"][0]["record_type"] == "A"


@patch("cli.interface.DNSResolver")
def test_cli_format_json_output_file_skips_human(mock_resolver_cls, tmp_path: Path, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    path = tmp_path / "only.json"

    assert run(["example.com", "--format", "json", "--output", str(path)]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Wrote" in captured.err
    assert json.loads(path.read_text(encoding="utf-8"))["mode"] == "forward"


@patch("cli.interface.DNSResolver")
def test_cli_reverse_format_json(mock_resolver_cls, capsys) -> None:
    mock_resolver_cls.return_value.resolve_reverse.return_value = [
        DNSRecord("PTR", "8.8.8.8.in-addr.arpa", "dns.google", 86400),
    ]

    assert run(["--reverse", "8.8.8.8", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["mode"] == "reverse"
    assert data["target"] == "8.8.8.8"
    assert data["ptr_query"] == "8.8.8.8.in-addr.arpa"
    assert data["records"][0]["value"] == "dns.google"
    assert data["security_analysis"] is None


def test_cli_rejects_output_txt_in_text_mode(capsys) -> None:
    assert run(["example.com", "--output", "out.txt"]) == 1
    assert ".json or .csv" in capsys.readouterr().err


def test_cli_rejects_format_output_mismatch(capsys) -> None:
    assert run(["example.com", "--format", "json", "--output", "out.csv"]) == 1
    assert "does not match" in capsys.readouterr().err


def test_cli_usage_without_domain(capsys) -> None:
    assert run([]) == 0
    assert "Usage:" in capsys.readouterr().out


def test_cli_rejects_domain_and_reverse(capsys) -> None:
    assert run(["example.com", "--reverse", "8.8.8.8"]) == 1
    assert "not both" in capsys.readouterr().err


def test_cli_rejects_invalid_reverse_ip(capsys) -> None:
    assert run(["--reverse", "not-an-ip"]) == 1
    assert "Invalid IP" in capsys.readouterr().err


@patch("cli.interface.DNSResolver")
def test_cli_nxdomain_exits_one(mock_resolver_cls, capsys) -> None:
    mock_resolver_cls.return_value.lookup_core.side_effect = DomainNotFoundError()
    assert run(["missing.example"]) == 1
    assert "does not exist" in capsys.readouterr().err
    mock_resolver_cls.return_value.inspect_dnssec.assert_not_called()


@patch("cli.interface.DNSResolver")
def test_cli_timeout_exits_one(mock_resolver_cls, capsys) -> None:
    mock_resolver_cls.return_value.lookup_core.side_effect = DNSTimeoutError()
    assert run(["example.com"]) == 1
    assert "timed out" in capsys.readouterr().err


def test_plan_export_text_is_human_only() -> None:
    plan = plan_export("text", None)
    assert isinstance(plan, ExportPlan)
    assert plan.print_human is True
    assert plan.file_format is None
    assert plan.path is None


def test_plan_export_json_stdout() -> None:
    plan = plan_export("json", None)
    assert isinstance(plan, ExportPlan)
    assert plan.print_human is False
    assert plan.file_format == "json"
    assert plan.path is None
