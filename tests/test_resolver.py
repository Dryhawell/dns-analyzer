"""Mocked tests for DNSResolver. No real nameservers are contacted."""

from __future__ import annotations

import logging
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


def test_resolve_aaaa_returns_records(resolver: DNSResolver) -> None:
    resolver._client.resolve.return_value = _answer(
        DummyRdata("2001:0db8:0000:0000:0000:0000:0000:0001")
    )

    records = resolver.resolve_aaaa("example.com")

    assert records[0].record_type == "AAAA"
    assert records[0].value == "2001:db8::1"
    resolver._client.resolve.assert_called_once_with("example.com", "AAAA", search=False)


def test_resolve_addresses_queries_a_then_aaaa(resolver: DNSResolver) -> None:
    resolver._client.resolve.side_effect = [
        _answer(DummyRdata("93.184.216.34")),
        _answer(DummyRdata("2001:db8::1")),
    ]

    ipv4, ipv6 = resolver.resolve_addresses("example.com")

    assert ipv4[0].value == "93.184.216.34"
    assert ipv6[0].value == "2001:db8::1"
    assert resolver._client.resolve.call_args_list[0].args[1] == "A"
    assert resolver._client.resolve.call_args_list[1].args[1] == "AAAA"


def test_lookup_core_queries_cname_mx_ns(resolver: DNSResolver) -> None:
    resolver._client.resolve.side_effect = [
        _answer(DummyRdata("93.184.216.34")),
        _answer(),
        _answer(DummyRdata("target.example.net.")),
        _answer(DummyRdata("10 mail.example.com.", preference=10, exchange="mail.example.com.")),
        _answer(DummyRdata("ns1.example.com.")),
        _answer(DummyRdata("ignored", strings=(b"v=spf1 -all",))),
        _answer(
            DummyRdata(
                "unused",
                mname="ns1.example.com.",
                rname="hostmaster.example.com.",
                serial=1,
                refresh=1,
                retry=1,
                expire=1,
                minimum=1,
            )
        ),
        _answer(DummyRdata("unused", flags=0, tag="issue", value="letsencrypt.org")),
    ]

    lookup = resolver.lookup_core("www.example.com")

    assert lookup.a[0].value == "93.184.216.34"
    assert lookup.aaaa == ()
    assert lookup.cname[0].value == "target.example.net"
    assert lookup.mx[0].value == "mail.example.com"
    assert lookup.mx[0].priority == 10
    assert lookup.ns[0].value == "ns1.example.com"
    assert lookup.txt[0].value == "v=spf1 -all"
    assert lookup.soa[0].details[0][1] == "ns1.example.com"
    assert lookup.caa[0].value == '0 issue "letsencrypt.org"'
    queried_types = [call.args[1] for call in resolver._client.resolve.call_args_list]
    assert queried_types == ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]


def test_lookup_core_keeps_results_if_caa_times_out(resolver: DNSResolver) -> None:
    resolver._client.resolve.side_effect = [
        _answer(DummyRdata("93.184.216.34")),
        _answer(),
        _answer(),
        _answer(),
        _answer(),
        _answer(),
        _answer(),
        dns.exception.Timeout(),
    ]

    lookup = resolver.lookup_core("example.com")

    assert lookup.a[0].value == "93.184.216.34"
    assert lookup.caa == ()
    assert lookup.errors == (("CAA", "DNS query timed out."),)


def test_resolve_mx_includes_preference(resolver: DNSResolver) -> None:
    rdata = DummyRdata("10 mail.example.com.", preference=10, exchange="mail.example.com.")
    resolver._client.resolve.return_value = _answer(rdata)

    records = resolver.resolve_mx("example.com")

    assert records[0].value == "mail.example.com"
    assert records[0].priority == 10


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


def test_timeout_raises(resolver: DNSResolver, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="dns_analyzer.resolver")
    resolver._client.resolve.side_effect = dns.exception.Timeout()

    with pytest.raises(DNSTimeoutError, match="timed out"):
        resolver.resolve_ns("example.com")

    assert "Querying NS record for example.com" in caplog.text
    assert "DNS query timeout for NS example.com" in caplog.text


def test_query_log_does_not_include_rdata(
    resolver: DNSResolver, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="dns_analyzer.resolver")
    resolver._client.resolve.return_value = _answer(DummyRdata("93.184.216.34"))

    records = resolver.resolve_a("example.com")

    assert records[0].value == "93.184.216.34"
    assert "Querying A record for example.com" in caplog.text
    assert "Received 1 A record(s) for example.com" in caplog.text
    assert "93.184.216.34" not in caplog.text


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


def test_resolve_reverse_queries_ptr_zone(resolver: DNSResolver) -> None:
    resolver._client.resolve.return_value = _answer(DummyRdata("dns.google."))

    records = resolver.resolve_reverse("8.8.8.8")

    assert records[0].value == "dns.google"
    resolver._client.resolve.assert_called_once_with(
        "8.8.8.8.in-addr.arpa", "PTR", search=False
    )


def test_resolve_reverse_nxdomain_is_empty(resolver: DNSResolver) -> None:
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()

    assert resolver.resolve_reverse("203.0.113.1") == []
