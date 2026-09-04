"""Mocked tests for DNSResolver. No real nameservers are contacted."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

import dns.exception
import dns.resolver
import pytest

from analyzer.exceptions import (
    DNSNetworkError,
    DNSResolutionError,
    DNSTimeoutError,
    DomainNotFoundError,
    NoNameserversError,
)
from analyzer.resolver import CORE_TYPES, DNSResolver, _normalize_types


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


def _dispatch(resolver: DNSResolver, answers: dict[str, object]) -> None:
    """Return/raise by rdtype. Parallel lookups cannot share a side_effect list."""

    def resolve(name: str, rdtype: str, search: bool = False):
        value = answers[rdtype]
        if isinstance(value, BaseException):
            raise value
        if isinstance(value, type) and issubclass(value, BaseException):
            raise value()
        return value

    resolver._client.resolve.side_effect = resolve


def _core_answers(**overrides: object) -> dict[str, object]:
    answers: dict[str, object] = {label: _answer() for label in CORE_TYPES}
    answers.update(overrides)
    return answers


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
    _dispatch(
        resolver,
        _core_answers(
            A=_answer(DummyRdata("93.184.216.34")),
            CNAME=_answer(DummyRdata("target.example.net.")),
            MX=_answer(DummyRdata("10 mail.example.com.", preference=10, exchange="mail.example.com.")),
            NS=_answer(DummyRdata("ns1.example.com.")),
            TXT=_answer(DummyRdata("ignored", strings=(b"v=spf1 -all",))),
            SOA=_answer(
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
            CAA=_answer(DummyRdata("unused", flags=0, tag="issue", value="letsencrypt.org")),
        ),
    )

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
    assert queried_types[0] == "A"
    assert set(queried_types) == set(CORE_TYPES)
    assert len(queried_types) == len(CORE_TYPES)


def test_lookup_core_keeps_results_if_caa_times_out(resolver: DNSResolver) -> None:
    _dispatch(
        resolver,
        _core_answers(
            A=_answer(DummyRdata("93.184.216.34")),
            CAA=dns.exception.Timeout(),
        ),
    )

    lookup = resolver.lookup_core("example.com")

    assert lookup.a[0].value == "93.184.216.34"
    assert lookup.caa == ()
    assert lookup.errors == (("CAA", "DNS query timed out."),)


def test_lookup_core_queries_only_requested_types(resolver: DNSResolver) -> None:
    def resolve(name: str, rdtype: str, search: bool = False):
        if rdtype == "A":
            return _answer(DummyRdata("93.184.216.34"))
        if rdtype == "MX":
            return _answer(
                DummyRdata("10 mail.example.com.", preference=10, exchange="mail.example.com.")
            )
        raise AssertionError(f"unexpected type {rdtype}")

    resolver._client.resolve.side_effect = resolve

    lookup = resolver.lookup_core("example.com", types=("MX",))

    queried = [call.args[1] for call in resolver._client.resolve.call_args_list]
    assert queried == ["A", "MX"]
    assert lookup.mx[0].value == "mail.example.com"
    assert lookup.ns == ()
    assert lookup.txt == ()


def test_lookup_core_a_only_skips_later_types(resolver: DNSResolver) -> None:
    resolver._client.resolve.return_value = _answer(DummyRdata("93.184.216.34"))

    lookup = resolver.lookup_core("example.com", types=("A",))

    assert lookup.a[0].value == "93.184.216.34"
    assert lookup.mx == ()
    resolver._client.resolve.assert_called_once_with("example.com", "A", search=False)


def test_normalize_types_always_includes_a() -> None:
    assert _normalize_types(None) == CORE_TYPES
    assert _normalize_types(("MX",)) == ("A", "MX")
    assert _normalize_types(()) == ("A",)


def test_lookup_core_a_nxdomain_does_not_query_later_types(resolver: DNSResolver) -> None:
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()

    with pytest.raises(DomainNotFoundError):
        resolver.lookup_core("missing.example")

    resolver._client.resolve.assert_called_once_with("missing.example", "A", search=False)


def test_lookup_core_later_nxdomain_is_not_existence_error(resolver: DNSResolver) -> None:
    _dispatch(
        resolver,
        _core_answers(
            A=_answer(DummyRdata("93.184.216.34")),
            MX=dns.resolver.NXDOMAIN(),
        ),
    )

    lookup = resolver.lookup_core("example.com", types=("MX",))

    assert lookup.a[0].value == "93.184.216.34"
    assert lookup.mx == ()
    assert lookup.errors[0][0] == "MX"
    assert "NXDOMAIN" in lookup.errors[0][1]
    assert "does not exist" not in lookup.errors[0][1]


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


def test_oserror_becomes_network_error(resolver: DNSResolver) -> None:
    resolver._client.resolve.side_effect = OSError("unreachable")

    with pytest.raises(DNSNetworkError, match="Network error"):
        resolver.resolve_a("example.com")


def test_custom_nameservers_are_applied() -> None:
    resolver = DNSResolver(timeout=1.5, nameservers=["1.1.1.1"])

    assert resolver._client.nameservers == ["1.1.1.1"]
    assert resolver._client.timeout == 1.5
    assert resolver._client.lifetime == 1.5


def test_lifetime_allows_nameserver_failover() -> None:
    resolver = DNSResolver(timeout=2.0, nameservers=["192.0.2.1", "192.0.2.2"])
    assert resolver._client.timeout == 2.0
    assert resolver._client.lifetime == 4.0


def test_edns_client_reuses_nameservers_without_os_config() -> None:
    resolver = DNSResolver(timeout=1.5, nameservers=["192.0.2.53"])
    client = resolver._edns_client()
    assert client.nameservers == ["192.0.2.53"]
    assert client.timeout == 1.5
    assert client.lifetime == 1.5


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
