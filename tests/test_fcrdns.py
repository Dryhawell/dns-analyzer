"""FCrDNS tests. No network access."""

from unittest.mock import MagicMock

from analyzer.exceptions import DNSTimeoutError
from analyzer.fcrdns import FcrdnsCheck, MAX_ADDRESSES, evaluate_fcrdns
from analyzer.models import CoreLookup, DNSRecord
from analyzer.resolver import DNSResolver


def _lookup(a: list[DNSRecord] | None = None, aaaa: list[DNSRecord] | None = None) -> CoreLookup:
    return CoreLookup(
        a=tuple(a or []),
        aaaa=tuple(aaaa or []),
        cname=(),
        mx=(),
        ns=(),
        txt=(),
        soa=(),
        caa=(),
    )


def test_evaluate_fcrdns_wraps_checks() -> None:
    check = FcrdnsCheck(
        ip="93.184.216.34",
        ptr_query="34.216.184.93.in-addr.arpa",
        ptr_names=("example.com",),
        forward_ips=("93.184.216.34",),
        status="CONFIRMED",
    )
    observation = evaluate_fcrdns([check], truncated=True)
    assert observation.truncated is True
    assert observation.checks[0].status == "CONFIRMED"


def test_inspect_fcrdns_confirmed() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_reverse = MagicMock(  # type: ignore[method-assign]
        return_value=[DNSRecord("PTR", "34.216.184.93.in-addr.arpa", "example.com", 60)]
    )
    resolver.resolve_a = MagicMock(  # type: ignore[method-assign]
        return_value=[DNSRecord("A", "example.com", "93.184.216.34", 60)]
    )
    observation = resolver.inspect_fcrdns(
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)])
    )
    assert observation.checks[0].status == "CONFIRMED"
    assert observation.checks[0].ptr_names == ("example.com",)
    resolver.resolve_reverse.assert_called_once_with("93.184.216.34")
    resolver.resolve_a.assert_called_once_with("example.com")


def test_inspect_fcrdns_no_ptr() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_reverse = MagicMock(return_value=[])  # type: ignore[method-assign]
    observation = resolver.inspect_fcrdns(
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)])
    )
    assert observation.checks[0].status == "NO PTR"
    assert observation.checks[0].ptr_query == "34.216.184.93.in-addr.arpa"


def test_inspect_fcrdns_mismatch() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_reverse = MagicMock(  # type: ignore[method-assign]
        return_value=[DNSRecord("PTR", "34.216.184.93.in-addr.arpa", "other.example", 60)]
    )
    resolver.resolve_a = MagicMock(  # type: ignore[method-assign]
        return_value=[DNSRecord("A", "other.example", "192.0.2.1", 60)]
    )
    observation = resolver.inspect_fcrdns(
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)])
    )
    assert observation.checks[0].status == "MISMATCH"
    assert "192.0.2.1" in observation.checks[0].forward_ips


def test_inspect_fcrdns_timeout_is_unreadable() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_reverse = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]
    observation = resolver.inspect_fcrdns(
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)])
    )
    assert observation.checks[0].status == "UNREADABLE"
    assert observation.checks[0].error is not None


def test_inspect_fcrdns_caps_addresses() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_reverse = MagicMock(return_value=[])  # type: ignore[method-assign]
    many = [
        DNSRecord("A", "example.com", f"203.0.113.{index}", 60)
        for index in range(MAX_ADDRESSES + 3)
    ]
    observation = resolver.inspect_fcrdns(_lookup(a=many))
    assert len(observation.checks) == MAX_ADDRESSES
    assert observation.truncated is True
    assert resolver.resolve_reverse.call_count == MAX_ADDRESSES
