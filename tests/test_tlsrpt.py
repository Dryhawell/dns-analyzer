"""TLS-RPT TXT parsing tests. No network access."""

from unittest.mock import MagicMock

import dns.resolver

from analyzer.exceptions import DNSTimeoutError
from analyzer.models import DNSRecord
from analyzer.resolver import DNSResolver
from analyzer.tlsrpt import evaluate_tls_rpt, tls_rpt_query_name


def _txt(value: str) -> list[DNSRecord]:
    return [DNSRecord("TXT", "_smtp._tls.example.com", value, 300)]


def test_tls_rpt_query_name() -> None:
    assert tls_rpt_query_name("Example.COM") == "_smtp._tls.example.com"


def test_tls_rpt_not_detected() -> None:
    observation = evaluate_tls_rpt("_smtp._tls.example.com", [])
    assert observation.status == "NOT DETECTED"
    assert observation.rua is None


def test_tls_rpt_found() -> None:
    observation = evaluate_tls_rpt(
        "_smtp._tls.example.com",
        _txt("v=TLSRPTv1; rua=mailto:tlsrpt@example.com"),
    )
    assert observation.status == "FOUND"
    assert observation.rua == "mailto:tlsrpt@example.com"


def test_tls_rpt_requires_semicolon_after_version() -> None:
    observation = evaluate_tls_rpt(
        "_smtp._tls.example.com",
        _txt("v=TLSRPTv1 rua=mailto:tlsrpt@example.com"),
    )
    assert observation.status == "NOT DETECTED"


def test_tls_rpt_found_without_rua() -> None:
    observation = evaluate_tls_rpt("_smtp._tls.example.com", _txt("v=TLSRPTv1;"))
    assert observation.status == "FOUND"
    assert observation.rua is None


def test_multiple_tls_rpt_records() -> None:
    observation = evaluate_tls_rpt(
        "_smtp._tls.example.com",
        _txt("v=TLSRPTv1; rua=mailto:a@example.com")
        + _txt("v=TLSRPTv1; rua=mailto:b@example.com"),
    )
    assert observation.multiple_records is True
    assert observation.rua == "mailto:a@example.com"


def test_inspect_tls_rpt_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._client = MagicMock()
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()

    observation = resolver.inspect_tls_rpt("example.com")

    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "_smtp._tls.example.com"


def test_inspect_tls_rpt_timeout_has_error() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_txt = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]

    observation = resolver.inspect_tls_rpt("example.com")

    assert observation.status == "NOT DETECTED"
    assert observation.error is not None


def test_inspect_tls_rpt_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_txt = MagicMock(  # type: ignore[method-assign]
        return_value=_txt("v=TLSRPTv1; rua=https://reporting.example.com/v1")
    )
    observation = resolver.inspect_tls_rpt("example.com")
    assert observation.status == "FOUND"
    assert observation.rua == "https://reporting.example.com/v1"
    resolver.resolve_txt.assert_called_once_with("_smtp._tls.example.com")
