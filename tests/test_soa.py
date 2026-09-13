"""SOA vs NS tests. No network access."""

from unittest.mock import MagicMock

from analyzer.exceptions import DNSTimeoutError, DomainNotFoundError
from analyzer.models import DNSRecord
from analyzer.resolver import DNSResolver
from analyzer.soa import evaluate_soa_ns, soa_primary, soa_serial


def _soa(mname: str = "ns1.example.com", serial: str = "2026091301") -> DNSRecord:
    return DNSRecord(
        "SOA",
        "example.com",
        f"{mname} serial={serial}",
        60,
        details=(("Primary NS", mname), ("Serial", serial)),
    )


def test_evaluate_soa_ns_aligned() -> None:
    observation = evaluate_soa_ns(
        "example.com",
        "ns1.example.com",
        ("ns1.example.com", "ns2.example.com"),
        serial="1",
    )
    assert observation.status == "ALIGNED"


def test_evaluate_soa_ns_hidden_primary() -> None:
    observation = evaluate_soa_ns(
        "example.com",
        "hidden.example.net",
        ("ns1.example.com", "ns2.example.com"),
    )
    assert observation.status == "HIDDEN PRIMARY"


def test_evaluate_soa_ns_not_detected() -> None:
    observation = evaluate_soa_ns("www.example.com", None, ())
    assert observation.status == "NOT DETECTED"


def test_evaluate_soa_ns_no_ns() -> None:
    observation = evaluate_soa_ns("example.com", "ns1.example.com", ())
    assert observation.status == "NO NS"


def test_evaluate_soa_ns_timeout_is_unreadable() -> None:
    observation = evaluate_soa_ns(
        "example.com", None, (), error="DNS query timed out."
    )
    assert observation.status == "UNREADABLE"


def test_soa_primary_and_serial_from_details() -> None:
    record = _soa()
    assert soa_primary(record) == "ns1.example.com"
    assert soa_serial(record) == "2026091301"


def test_inspect_soa_ns_aligned() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_soa = MagicMock(return_value=[_soa()])  # type: ignore[method-assign]
    resolver.resolve_ns = MagicMock(  # type: ignore[method-assign]
        return_value=[
            DNSRecord("NS", "example.com", "ns1.example.com", 60),
            DNSRecord("NS", "example.com", "ns2.example.com", 60),
        ]
    )
    observation = resolver.inspect_soa_ns("example.com")
    assert observation.status == "ALIGNED"
    assert observation.mname == "ns1.example.com"
    assert "ns2.example.com" in observation.ns_hosts
    resolver.resolve_soa.assert_called_once_with("example.com")
    resolver.resolve_ns.assert_called_once_with("example.com")


def test_inspect_soa_ns_hidden_primary() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_soa = MagicMock(  # type: ignore[method-assign]
        return_value=[_soa("hidden.example.net")]
    )
    resolver.resolve_ns = MagicMock(  # type: ignore[method-assign]
        return_value=[DNSRecord("NS", "example.com", "ns1.example.com", 60)]
    )
    observation = resolver.inspect_soa_ns("example.com")
    assert observation.status == "HIDDEN PRIMARY"


def test_inspect_soa_ns_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_soa = MagicMock(side_effect=DomainNotFoundError())  # type: ignore[method-assign]
    observation = resolver.inspect_soa_ns("www.example.com")
    assert observation.status == "NOT DETECTED"


def test_inspect_soa_ns_timeout_is_unreadable() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_soa = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]
    observation = resolver.inspect_soa_ns("example.com")
    assert observation.status == "UNREADABLE"


def test_inspect_soa_ns_ns_timeout_is_unreadable() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_soa = MagicMock(return_value=[_soa()])  # type: ignore[method-assign]
    resolver.resolve_ns = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]
    observation = resolver.inspect_soa_ns("example.com")
    assert observation.status == "UNREADABLE"
    assert observation.mname == "ns1.example.com"
