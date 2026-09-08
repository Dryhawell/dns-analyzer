"""BIMI TXT parsing tests. No network access."""

from unittest.mock import MagicMock

import dns.resolver

from analyzer.exceptions import DNSTimeoutError
from analyzer.models import DNSRecord
from analyzer.resolver import DNSResolver
from analyzer.bimi import evaluate_bimi, bimi_query_name


def _txt(value: str) -> list[DNSRecord]:
    return [DNSRecord("TXT", "default._bimi.example.com", value, 300)]


def test_bimi_query_name() -> None:
    assert bimi_query_name("Example.COM") == "default._bimi.example.com"


def test_bimi_not_detected() -> None:
    observation = evaluate_bimi("default._bimi.example.com", "default", [])
    assert observation.status == "NOT DETECTED"
    assert observation.location is None
    assert observation.authority is None


def test_bimi_found() -> None:
    observation = evaluate_bimi(
        "default._bimi.example.com",
        "default",
        _txt("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"),
    )
    assert observation.status == "FOUND"
    assert observation.selector == "default"
    assert observation.location == "https://example.com/logo.svg"
    assert observation.authority == "https://example.com/vmc.pem"


def test_bimi_requires_semicolon_after_version() -> None:
    observation = evaluate_bimi(
        "default._bimi.example.com",
        "default",
        _txt("v=BIMI1 l=https://example.com/logo.svg"),
    )
    assert observation.status == "NOT DETECTED"


def test_bimi_found_without_location() -> None:
    observation = evaluate_bimi(
        "default._bimi.example.com",
        "default",
        _txt("v=BIMI1;"),
    )
    assert observation.status == "FOUND"
    assert observation.location is None


def test_multiple_bimi_records() -> None:
    observation = evaluate_bimi(
        "default._bimi.example.com",
        "default",
        _txt("v=BIMI1; l=https://a.example/logo.svg")
        + _txt("v=BIMI1; l=https://b.example/logo.svg"),
    )
    assert observation.multiple_records is True
    assert observation.location == "https://a.example/logo.svg"


def test_inspect_bimi_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._client = MagicMock()
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()

    observation = resolver.inspect_bimi("example.com")

    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "default._bimi.example.com"
    assert observation.selector == "default"


def test_inspect_bimi_timeout_has_error() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_txt = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]

    observation = resolver.inspect_bimi("example.com")

    assert observation.status == "NOT DETECTED"
    assert observation.error is not None


def test_inspect_bimi_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_txt = MagicMock(  # type: ignore[method-assign]
        return_value=_txt("v=BIMI1; l=https://example.com/logo.svg")
    )
    observation = resolver.inspect_bimi("example.com")
    assert observation.status == "FOUND"
    assert observation.location == "https://example.com/logo.svg"
    resolver.resolve_txt.assert_called_once_with("default._bimi.example.com")
