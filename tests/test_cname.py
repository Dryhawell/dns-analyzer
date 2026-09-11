"""CNAME target lookup tests. No network access."""

from unittest.mock import MagicMock

from analyzer.cname import (
    MAX_TARGETS,
    CnameTargetCheck,
    evaluate_cname_targets,
    unique_cname_targets,
)
from analyzer.exceptions import DNSTimeoutError, DomainNotFoundError
from analyzer.models import CoreLookup, DNSRecord
from analyzer.resolver import DNSResolver


def _lookup(cname: list[DNSRecord] | None = None) -> CoreLookup:
    return CoreLookup(
        a=(),
        aaaa=(),
        cname=tuple(cname or []),
        mx=(),
        ns=(),
        txt=(),
        soa=(),
        caa=(),
    )


def test_evaluate_cname_targets_empty_is_not_detected() -> None:
    observation = evaluate_cname_targets(())
    assert observation.status == "NOT DETECTED"
    assert observation.checks == ()


def test_evaluate_cname_targets_wraps_checks() -> None:
    check = CnameTargetCheck(
        target="cdn.example.net",
        chain=("cdn.example.net",),
        ipv4=("192.0.2.10",),
        ipv6=(),
        status="RESOLVES",
    )
    observation = evaluate_cname_targets([check], truncated=True)
    assert observation.status == "FOUND"
    assert observation.truncated is True


def test_unique_cname_targets_preserves_order() -> None:
    records = [
        DNSRecord("CNAME", "www.example.com", "b.example.net", 60),
        DNSRecord("CNAME", "www.example.com", "a.example.net", 60),
        DNSRecord("CNAME", "www.example.com", "b.example.net", 60),
    ]
    assert unique_cname_targets(records) == ("b.example.net", "a.example.net")


def test_inspect_cname_targets_resolves() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_a = MagicMock(  # type: ignore[method-assign]
        return_value=[DNSRecord("A", "cdn.example.net", "192.0.2.10", 60)]
    )
    resolver.resolve_aaaa = MagicMock(return_value=[])  # type: ignore[method-assign]
    resolver.resolve_cname = MagicMock(return_value=[])  # type: ignore[method-assign]
    observation = resolver.inspect_cname_targets(
        _lookup([DNSRecord("CNAME", "www.example.com", "cdn.example.net", 60)])
    )
    assert observation.checks[0].status == "RESOLVES"
    assert observation.checks[0].ipv4 == ("192.0.2.10",)
    assert observation.checks[0].chain == ("cdn.example.net",)
    resolver.resolve_a.assert_called_once_with("cdn.example.net")


def test_inspect_cname_targets_follows_one_hop() -> None:
    resolver = DNSResolver(timeout=1.0)

    def _a(name: str) -> list[DNSRecord]:
        if name == "edge.example.net":
            return [DNSRecord("A", name, "192.0.2.20", 60)]
        return []

    def _cname(name: str) -> list[DNSRecord]:
        if name == "cdn.example.net":
            return [DNSRecord("CNAME", name, "edge.example.net", 60)]
        return []

    resolver.resolve_a = MagicMock(side_effect=_a)  # type: ignore[method-assign]
    resolver.resolve_aaaa = MagicMock(return_value=[])  # type: ignore[method-assign]
    resolver.resolve_cname = MagicMock(side_effect=_cname)  # type: ignore[method-assign]
    observation = resolver.inspect_cname_targets(
        _lookup([DNSRecord("CNAME", "www.example.com", "cdn.example.net", 60)])
    )
    assert observation.checks[0].status == "RESOLVES"
    assert observation.checks[0].chain == ("cdn.example.net", "edge.example.net")
    assert observation.checks[0].ipv4 == ("192.0.2.20",)


def test_inspect_cname_targets_nxdomain() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_a = MagicMock(side_effect=DomainNotFoundError())  # type: ignore[method-assign]
    resolver.resolve_aaaa = MagicMock(side_effect=DomainNotFoundError())  # type: ignore[method-assign]
    resolver.resolve_cname = MagicMock(side_effect=DomainNotFoundError())  # type: ignore[method-assign]
    observation = resolver.inspect_cname_targets(
        _lookup([DNSRecord("CNAME", "www.example.com", "gone.example.net", 60)])
    )
    assert observation.checks[0].status == "NXDOMAIN"


def test_inspect_cname_targets_loop() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_a = MagicMock(return_value=[])  # type: ignore[method-assign]
    resolver.resolve_aaaa = MagicMock(return_value=[])  # type: ignore[method-assign]

    def _cname(name: str) -> list[DNSRecord]:
        if name == "a.example.net":
            return [DNSRecord("CNAME", name, "b.example.net", 60)]
        return [DNSRecord("CNAME", name, "a.example.net", 60)]

    resolver.resolve_cname = MagicMock(side_effect=_cname)  # type: ignore[method-assign]
    observation = resolver.inspect_cname_targets(
        _lookup([DNSRecord("CNAME", "www.example.com", "a.example.net", 60)])
    )
    assert observation.checks[0].status == "LOOP"


def test_inspect_cname_targets_timeout_is_unreadable() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_a = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]
    resolver.resolve_aaaa = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]
    resolver.resolve_cname = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]
    observation = resolver.inspect_cname_targets(
        _lookup([DNSRecord("CNAME", "www.example.com", "cdn.example.net", 60)])
    )
    assert observation.checks[0].status == "UNREADABLE"


def test_inspect_cname_targets_caps_targets() -> None:
    resolver = DNSResolver(timeout=1.0)
    many = [
        DNSRecord("CNAME", "www.example.com", f"t{i}.example.net", 60)
        for i in range(MAX_TARGETS + 3)
    ]
    resolver.resolve_a = MagicMock(return_value=[])  # type: ignore[method-assign]
    resolver.resolve_aaaa = MagicMock(return_value=[])  # type: ignore[method-assign]
    resolver.resolve_cname = MagicMock(return_value=[])  # type: ignore[method-assign]
    observation = resolver.inspect_cname_targets(_lookup(many))
    assert len(observation.checks) == MAX_TARGETS
    assert observation.truncated is True
