"""CLI tests with a mocked resolver. No network access."""

from unittest.mock import patch

from analyzer.models import CoreLookup, DNSRecord
from cli.interface import run


def _lookup(
    a: list[DNSRecord] | None = None,
    aaaa: list[DNSRecord] | None = None,
    cname: list[DNSRecord] | None = None,
    mx: list[DNSRecord] | None = None,
    ns: list[DNSRecord] | None = None,
) -> CoreLookup:
    return CoreLookup(
        a=tuple(a or []),
        aaaa=tuple(aaaa or []),
        cname=tuple(cname or []),
        mx=tuple(mx or []),
        ns=tuple(ns or []),
    )


@patch("cli.interface.DNSResolver")
def test_cli_prints_a_and_aaaa(mock_resolver_cls, capsys) -> None:
    mock_resolver_cls.return_value.lookup_core.return_value = _lookup(
        a=[DNSRecord("A", "example.com", "93.184.216.34", 3600)],
        aaaa=[DNSRecord("AAAA", "example.com", "2001:db8::1", 300)],
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "Target:" in output
    assert "example.com" in output
    assert "A RECORDS" in output
    assert "93.184.216.34" in output
    assert "TTL: 3600" in output
    assert "AAAA RECORDS" in output
    assert "2001:db8::1" in output
    assert "TTL: 300" in output


@patch("cli.interface.DNSResolver")
def test_cli_missing_aaaa_is_not_an_error(mock_resolver_cls, capsys) -> None:
    mock_resolver_cls.return_value.lookup_core.return_value = _lookup(
        a=[DNSRecord("A", "example.com", "93.184.216.34", 3600)],
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "No AAAA record found." in output


@patch("cli.interface.DNSResolver")
def test_cli_notes_private_scope(mock_resolver_cls, capsys) -> None:
    mock_resolver_cls.return_value.lookup_core.return_value = _lookup(
        a=[DNSRecord("A", "intranet.example", "10.0.0.5", 60)],
    )

    assert run(["intranet.example"]) == 0
    assert "Scope: private" in capsys.readouterr().out


@patch("cli.interface.DNSResolver")
def test_cli_prints_cname_mx_ns(mock_resolver_cls, capsys) -> None:
    mock_resolver_cls.return_value.lookup_core.return_value = _lookup(
        cname=[DNSRecord("CNAME", "www.example.com", "example.com", 600)],
        mx=[
            DNSRecord("MX", "example.com", "mail-b.example.com", 3600, priority=20),
            DNSRecord("MX", "example.com", "mail-a.example.com", 3600, priority=10),
        ],
        ns=[
            DNSRecord("NS", "example.com", "ns2.example.com", 86400),
            DNSRecord("NS", "example.com", "ns1.example.com", 86400),
        ],
    )

    assert run(["www.example.com"]) == 0
    output = capsys.readouterr().out
    assert "www.example.com → example.com" in output
    assert "mail-a.example.com" in output
    assert output.find("mail-a.example.com") < output.find("mail-b.example.com")
    assert "Priority: 10" in output
    assert "Priority: 20" in output
    assert output.find("ns1.example.com") < output.find("ns2.example.com")
