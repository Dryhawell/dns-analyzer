"""Mocked tests for DNSResolver. No real nameservers are contacted."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import dns.exception
import dns.resolver
import pytest

from analyzer.exceptions import (
    DNSResolutionError,
    DNSTimeoutError,
    DomainNotFoundError,
    NoNameserversError,
)
from analyzer.resolver import DNSResolver


class DummyRdata:
    def __init__(self, text: str, **attrs: object) -> None:
        self._text = text
        for key, value in attrs.items():
            setattr(self, key, value)

    def __str__(self) -> str:
        return self._text


def _answer(*rdata: object, ttl: int = 3600) -> MagicMock:
    answer = MagicMock()
    answer.ttl = ttl
    answer.__iter__.return_value = iter(rdata)
    return answer


@pytest.fixture
def resolver() -> DNSResolver:
    client = DNSResolver(timeout=2.0)
    client._client = MagicMock()
    return client


def test_resolve_a_returns_records(resolver: DNSResolver) -> None:
    resolver._client.resolve.return_value = _answer(DummyRdata("93.184.216.34"))

    records = resolver.resolve_a("example.com")

    assert len(records) == 1
    assert records[0].record_type == "A"
    assert records[0].name == "example.com"
    assert records[0].value == "93.184.216.34"
    assert records[0].ttl == 3600
    resolver._client.resolve.assert_called_once_with("example.com", "A", search=False)


def test_resolve_mx_includes_preference(resolver: DNSResolver) -> None:
    rdata = DummyRdata("10 mail.example.com.", preference=10, exchange="mail.example.com.")
    resolver._client.resolve.return_value = _answer(rdata)

    records = resolver.resolve_mx("example.com")

    assert records[0].value == "10 mail.example.com"


def test_resolve_txt_joins_strings(resolver: DNSResolver) -> None:
    rdata = DummyRdata("ignored", strings=(b"v=spf1 ", b"~all"))
    resolver._client.resolve.return_value = _answer(rdata)

    records = resolver.resolve_txt("example.com")

    assert records[0].value == "v=spf1 ~all"


def test_no_answer_returns_empty_list(resolver: DNSResolver) -> None:
    resolver._client.resolve.side_effect = dns.resolver.NoAnswer(
        response=SimpleNamespace(question="example.com IN AAAA")
    )

    assert resolver.resolve_aaaa("example.com") == []


def test_nxdomain_raises(resolver: DNSResolver) -> None:
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()

    with pytest.raises(DomainNotFoundError, match="does not exist"):
        resolver.resolve_a("no-such-domain.example")


def test_timeout_raises(resolver: DNSResolver) -> None:
    resolver._client.resolve.side_effect = dns.exception.Timeout()

    with pytest.raises(DNSTimeoutError, match="timed out"):
        resolver.resolve_ns("example.com")


def test_no_nameservers_raises(resolver: DNSResolver) -> None:
    resolver._client.resolve.side_effect = dns.resolver.NoNameservers(
        request=SimpleNamespace(question="example.com IN SOA"), errors=[]
    )

    with pytest.raises(NoNameserversError):
        resolver.resolve_soa("example.com")


def test_generic_dns_exception_raises(resolver: DNSResolver) -> None:
    resolver._client.resolve.side_effect = dns.exception.DNSException()

    with pytest.raises(DNSResolutionError):
        resolver.resolve_caa("example.com")


def test_custom_nameservers_are_applied() -> None:
    resolver = DNSResolver(timeout=1.5, nameservers=["1.1.1.1"])

    assert resolver._client.nameservers == ["1.1.1.1"]
    assert resolver._client.timeout == 1.5
    assert resolver._client.lifetime == 1.5
