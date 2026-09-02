"""CLI tests with a mocked resolver. No network access."""

from unittest.mock import patch

from analyzer.models import DNSRecord
from cli.interface import run


@patch("cli.interface.DNSResolver")
def test_cli_prints_a_and_aaaa(mock_resolver_cls, capsys) -> None:
    mock_resolver_cls.return_value.resolve_addresses.return_value = (
        [DNSRecord("A", "example.com", "93.184.216.34", 3600)],
        [DNSRecord("AAAA", "example.com", "2001:db8::1", 300)],
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
    mock_resolver_cls.return_value.resolve_addresses.return_value = (
        [DNSRecord("A", "example.com", "93.184.216.34", 3600)],
        [],
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "No AAAA record found." in output


@patch("cli.interface.DNSResolver")
def test_cli_notes_private_scope(mock_resolver_cls, capsys) -> None:
    mock_resolver_cls.return_value.resolve_addresses.return_value = (
        [DNSRecord("A", "intranet.example", "10.0.0.5", 60)],
        [],
    )

    assert run(["intranet.example"]) == 0
    assert "Scope: private" in capsys.readouterr().out
