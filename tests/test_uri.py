"""URI listing tests. No network access. Targets are never fetched."""

from unittest.mock import MagicMock

import dns.resolver

from analyzer.exceptions import DNSTimeoutError
from analyzer.models import DNSRecord
from analyzer.resolver import DNSResolver
from analyzer.uri import (
    MAX_URI,
    evaluate_uri,
    scheme_meaning,
    target_from_record,
    uri_scheme,
)


def _uri(
    value: str = '10 1 "https://www.example.com/path"',
    name: str = "example.com",
) -> list[DNSRecord]:
    return [DNSRecord("URI", name, value, 300)]


def test_uri_scheme_and_meaning() -> None:
    assert uri_scheme("https://www.example.com/logo.svg") == "https"
    assert uri_scheme("SIP:user@example.com") == "sip"
    assert uri_scheme("not-a-uri") == ""
    assert "does not fetch" in scheme_meaning("https")
    assert "does not send mail" in scheme_meaning("mailto")
    assert "does not follow" in scheme_meaning("ldap")
    assert scheme_meaning("") == "no scheme"


def test_uri_not_detected() -> None:
    observation = evaluate_uri("Example.COM", [])
    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "example.com"
    assert observation.uris == ()


def test_uri_found_sorts_priority_then_weight() -> None:
    low = DNSRecord("URI", "example.com", '20 1 "https://b.example.com/"', 60)
    high = DNSRecord("URI", "example.com", '10 5 "https://a.example.com/"', 60)
    same = DNSRecord("URI", "example.com", '10 1 "ftp://ftp.example.com/pub"', 60)
    observation = evaluate_uri("example.com", [low, high, same])
    assert observation.status == "FOUND"
    assert observation.uris[0].priority == 10
    assert observation.uris[0].weight == 1
    assert observation.uris[0].scheme == "ftp"
    assert observation.uris[1].priority == 10
    assert observation.uris[1].weight == 5
    assert observation.uris[2].priority == 20


def test_uri_does_not_fetch_target() -> None:
    record = DNSRecord(
        "URI",
        "example.com",
        '10 1 "https://www.example.com/secret"',
        60,
    )
    observation = evaluate_uri("example.com", [record])
    assert observation.uris[0].target == "https://www.example.com/secret"
    assert "does not fetch" in observation.note
    assert "does not fetch" in observation.uris[0].scheme_meaning


def test_uri_caps_at_eight() -> None:
    records = [
        DNSRecord("URI", "example.com", f'{i} 0 "https://n{i}.example.com/"', 60)
        for i in range(MAX_URI + 2)
    ]
    observation = evaluate_uri("example.com", records)
    assert len(observation.uris) == MAX_URI
    assert observation.truncated is True


def test_target_from_record_fallback_split() -> None:
    record = DNSRecord(
        "URI",
        "example.com",
        "10 20 http://www.example.com/pub",
        60,
    )
    item = target_from_record(record)
    assert item is not None
    assert item.priority == 10
    assert item.weight == 20
    assert item.target == "http://www.example.com/pub"
    assert item.scheme == "http"


def test_inspect_uri_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._client = MagicMock()
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()

    observation = resolver.inspect_uri("example.com")

    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "example.com"


def test_inspect_uri_timeout_is_not_detected_with_error() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_uri = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]

    observation = resolver.inspect_uri("Example.COM.")

    assert observation.status == "NOT DETECTED"
    assert observation.error is not None
    resolver.resolve_uri.assert_called_once_with("example.com")


def test_inspect_uri_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_uri = MagicMock(return_value=_uri())  # type: ignore[method-assign]
    observation = resolver.inspect_uri("example.com")
    assert observation.status == "FOUND"
    assert observation.uris[0].scheme == "https"
    resolver.resolve_uri.assert_called_once_with("example.com")
