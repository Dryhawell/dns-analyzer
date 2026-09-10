"""MX host lookup tests. No network access."""

from unittest.mock import MagicMock

from analyzer.exceptions import DNSTimeoutError, DomainNotFoundError
from analyzer.models import DNSRecord
from analyzer.mx import (
    MAX_HOSTS,
    MxHostCheck,
    evaluate_mx_hosts,
    mx_host_name,
    unique_mx_hosts,
)
from analyzer.resolver import DNSResolver


def test_evaluate_mx_hosts_empty_is_not_detected() -> None:
    observation = evaluate_mx_hosts("example.com", ())
    assert observation.status == "NOT DETECTED"
    assert observation.checks == ()


def test_evaluate_mx_hosts_timeout_is_unreadable() -> None:
    observation = evaluate_mx_hosts("example.com", (), error="DNS query timed out.")
    assert observation.status == "UNREADABLE"
    assert observation.error == "DNS query timed out."


def test_evaluate_mx_hosts_wraps_checks() -> None:
    check = MxHostCheck(
        host="mail.example.com",
        preference=10,
        ipv4=("192.0.2.10",),
        ipv6=(),
        status="RESOLVES",
    )
    observation = evaluate_mx_hosts("example.com", [check], truncated=True)
    assert observation.status == "FOUND"
    assert observation.truncated is True
    assert observation.checks[0].status == "RESOLVES"


def test_mx_host_name_null_mx() -> None:
    assert mx_host_name(".") == "."
    assert mx_host_name("") == "."
    assert mx_host_name("Mail.Example.COM.") == "mail.example.com"


def test_unique_mx_hosts_orders_by_preference() -> None:
    records = [
        DNSRecord("MX", "example.com", "b.example.com", 60, priority=20),
        DNSRecord("MX", "example.com", "a.example.com", 60, priority=10),
        DNSRecord("MX", "example.com", "a.example.com", 60, priority=10),
    ]
    hosts = unique_mx_hosts(records)
    assert hosts == (("a.example.com", 10), ("b.example.com", 20))


def test_inspect_mx_hosts_resolves() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_mx = MagicMock(  # type: ignore[method-assign]
        return_value=[
            DNSRecord("MX", "example.com", "mail.example.com", 60, priority=10),
        ]
    )
    resolver.resolve_a = MagicMock(  # type: ignore[method-assign]
        return_value=[DNSRecord("A", "mail.example.com", "192.0.2.10", 60)]
    )
    resolver.resolve_aaaa = MagicMock(return_value=[])  # type: ignore[method-assign]
    observation = resolver.inspect_mx_hosts("example.com")
    assert observation.status == "FOUND"
    assert observation.checks[0].status == "RESOLVES"
    assert observation.checks[0].ipv4 == ("192.0.2.10",)
    resolver.resolve_mx.assert_called_once_with("example.com")
    resolver.resolve_a.assert_called_once_with("mail.example.com")


def test_inspect_mx_hosts_nxdomain_target() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_mx = MagicMock(  # type: ignore[method-assign]
        return_value=[
            DNSRecord("MX", "example.com", "gone.example.net", 60, priority=10),
        ]
    )
    resolver.resolve_a = MagicMock(side_effect=DomainNotFoundError())  # type: ignore[method-assign]
    resolver.resolve_aaaa = MagicMock(side_effect=DomainNotFoundError())  # type: ignore[method-assign]
    observation = resolver.inspect_mx_hosts("example.com")
    assert observation.checks[0].status == "NXDOMAIN"


def test_inspect_mx_hosts_no_address() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_mx = MagicMock(  # type: ignore[method-assign]
        return_value=[
            DNSRecord("MX", "example.com", "mail.example.com", 60, priority=10),
        ]
    )
    resolver.resolve_a = MagicMock(return_value=[])  # type: ignore[method-assign]
    resolver.resolve_aaaa = MagicMock(return_value=[])  # type: ignore[method-assign]
    observation = resolver.inspect_mx_hosts("example.com")
    assert observation.checks[0].status == "NO ADDRESS"


def test_inspect_mx_hosts_timeout_is_unreadable() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_mx = MagicMock(  # type: ignore[method-assign]
        return_value=[
            DNSRecord("MX", "example.com", "mail.example.com", 60, priority=10),
        ]
    )
    resolver.resolve_a = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]
    resolver.resolve_aaaa = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]
    observation = resolver.inspect_mx_hosts("example.com")
    assert observation.checks[0].status == "UNREADABLE"


def test_inspect_mx_hosts_null_mx_skips_address_lookup() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_mx = MagicMock(  # type: ignore[method-assign]
        return_value=[DNSRecord("MX", "example.com", ".", 60, priority=0)]
    )
    resolver.resolve_a = MagicMock()  # type: ignore[method-assign]
    resolver.resolve_aaaa = MagicMock()  # type: ignore[method-assign]
    observation = resolver.inspect_mx_hosts("example.com")
    assert observation.checks[0].status == "NULL MX"
    resolver.resolve_a.assert_not_called()
    resolver.resolve_aaaa.assert_not_called()


def test_inspect_mx_hosts_caps_hosts() -> None:
    resolver = DNSResolver(timeout=1.0)
    many = [
        DNSRecord("MX", "example.com", f"mail{i}.example.com", 60, priority=i)
        for i in range(MAX_HOSTS + 3)
    ]
    resolver.resolve_mx = MagicMock(return_value=many)  # type: ignore[method-assign]
    resolver.resolve_a = MagicMock(return_value=[])  # type: ignore[method-assign]
    resolver.resolve_aaaa = MagicMock(return_value=[])  # type: ignore[method-assign]
    observation = resolver.inspect_mx_hosts("example.com")
    assert len(observation.checks) == MAX_HOSTS
    assert observation.truncated is True
