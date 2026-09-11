"""NS host lookup tests. No network access."""

from unittest.mock import MagicMock

from analyzer.exceptions import DNSTimeoutError, DomainNotFoundError
from analyzer.models import DNSRecord
from analyzer.ns import (
    MAX_HOSTS,
    NsHostCheck,
    evaluate_ns_hosts,
    ns_in_bailiwick,
    unique_ns_hosts,
)
from analyzer.resolver import DNSResolver


def test_evaluate_ns_hosts_empty_is_not_detected() -> None:
    observation = evaluate_ns_hosts("example.com", ())
    assert observation.status == "NOT DETECTED"
    assert observation.checks == ()


def test_evaluate_ns_hosts_timeout_is_unreadable() -> None:
    observation = evaluate_ns_hosts("example.com", (), error="DNS query timed out.")
    assert observation.status == "UNREADABLE"
    assert observation.error == "DNS query timed out."


def test_evaluate_ns_hosts_wraps_checks() -> None:
    check = NsHostCheck(
        host="ns1.example.com",
        in_bailiwick=True,
        ipv4=("192.0.2.53",),
        ipv6=(),
        status="RESOLVES",
    )
    observation = evaluate_ns_hosts("example.com", [check], truncated=True)
    assert observation.status == "FOUND"
    assert observation.truncated is True
    assert observation.checks[0].in_bailiwick is True


def test_ns_in_bailiwick() -> None:
    assert ns_in_bailiwick("example.com", "ns1.example.com") is True
    assert ns_in_bailiwick("example.com", "example.com") is True
    assert ns_in_bailiwick("example.com", "ns1.cloudflare.com") is False
    assert ns_in_bailiwick("example.com", "notexample.com") is False


def test_unique_ns_hosts_preserves_order() -> None:
    records = [
        DNSRecord("NS", "example.com", "ns2.example.com", 60),
        DNSRecord("NS", "example.com", "ns1.example.com", 60),
        DNSRecord("NS", "example.com", "ns2.example.com", 60),
    ]
    assert unique_ns_hosts(records) == ("ns2.example.com", "ns1.example.com")


def test_inspect_ns_hosts_resolves() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_ns = MagicMock(  # type: ignore[method-assign]
        return_value=[DNSRecord("NS", "example.com", "ns1.example.com", 60)]
    )
    resolver.resolve_a = MagicMock(  # type: ignore[method-assign]
        return_value=[DNSRecord("A", "ns1.example.com", "192.0.2.53", 60)]
    )
    resolver.resolve_aaaa = MagicMock(return_value=[])  # type: ignore[method-assign]
    observation = resolver.inspect_ns_hosts("example.com")
    assert observation.status == "FOUND"
    assert observation.checks[0].status == "RESOLVES"
    assert observation.checks[0].in_bailiwick is True
    assert observation.checks[0].ipv4 == ("192.0.2.53",)
    resolver.resolve_ns.assert_called_once_with("example.com")
    resolver.resolve_a.assert_called_once_with("ns1.example.com")


def test_inspect_ns_hosts_out_of_bailiwick() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_ns = MagicMock(  # type: ignore[method-assign]
        return_value=[DNSRecord("NS", "example.com", "ns1.cloudflare.com", 60)]
    )
    resolver.resolve_a = MagicMock(  # type: ignore[method-assign]
        return_value=[DNSRecord("A", "ns1.cloudflare.com", "192.0.2.1", 60)]
    )
    resolver.resolve_aaaa = MagicMock(return_value=[])  # type: ignore[method-assign]
    observation = resolver.inspect_ns_hosts("example.com")
    assert observation.checks[0].in_bailiwick is False
    assert observation.checks[0].status == "RESOLVES"


def test_inspect_ns_hosts_nxdomain_target() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_ns = MagicMock(  # type: ignore[method-assign]
        return_value=[DNSRecord("NS", "example.com", "gone.example.net", 60)]
    )
    resolver.resolve_a = MagicMock(side_effect=DomainNotFoundError())  # type: ignore[method-assign]
    resolver.resolve_aaaa = MagicMock(side_effect=DomainNotFoundError())  # type: ignore[method-assign]
    observation = resolver.inspect_ns_hosts("example.com")
    assert observation.checks[0].status == "NXDOMAIN"


def test_inspect_ns_hosts_no_address() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_ns = MagicMock(  # type: ignore[method-assign]
        return_value=[DNSRecord("NS", "example.com", "ns1.example.com", 60)]
    )
    resolver.resolve_a = MagicMock(return_value=[])  # type: ignore[method-assign]
    resolver.resolve_aaaa = MagicMock(return_value=[])  # type: ignore[method-assign]
    observation = resolver.inspect_ns_hosts("example.com")
    assert observation.checks[0].status == "NO ADDRESS"


def test_inspect_ns_hosts_timeout_is_unreadable() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_ns = MagicMock(  # type: ignore[method-assign]
        return_value=[DNSRecord("NS", "example.com", "ns1.example.com", 60)]
    )
    resolver.resolve_a = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]
    resolver.resolve_aaaa = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]
    observation = resolver.inspect_ns_hosts("example.com")
    assert observation.checks[0].status == "UNREADABLE"


def test_inspect_ns_hosts_caps_hosts() -> None:
    resolver = DNSResolver(timeout=1.0)
    many = [
        DNSRecord("NS", "example.com", f"ns{i}.example.com", 60)
        for i in range(MAX_HOSTS + 3)
    ]
    resolver.resolve_ns = MagicMock(return_value=many)  # type: ignore[method-assign]
    resolver.resolve_a = MagicMock(return_value=[])  # type: ignore[method-assign]
    resolver.resolve_aaaa = MagicMock(return_value=[])  # type: ignore[method-assign]
    observation = resolver.inspect_ns_hosts("example.com")
    assert len(observation.checks) == MAX_HOSTS
    assert observation.truncated is True
