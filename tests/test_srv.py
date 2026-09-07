"""SRV service parsing tests. No network access."""

from unittest.mock import MagicMock

import dns.resolver
import pytest

from analyzer.exceptions import DNSTimeoutError
from analyzer.models import DNSRecord
from analyzer.resolver import DNSResolver
from analyzer.srv import (
    MAX_SRV,
    SrvSpec,
    SrvSpecError,
    evaluate_srv,
    normalize_srv_spec,
    normalize_srv_specs,
    srv_query_name,
)


def _srv(
    name: str = "_sip._tcp.example.com",
    value: str = "10 5 5060 sip.example.com",
    priority: int = 10,
) -> list[DNSRecord]:
    return [
        DNSRecord(
            "SRV",
            name,
            value,
            300,
            priority=priority,
            details=(
                ("Priority", f"{priority} — lower number is tried first"),
                ("Weight", "5 — among the same priority"),
                ("Port", "5060"),
                ("Target", "sip.example.com"),
            ),
        )
    ]


def test_srv_query_name() -> None:
    spec = SrvSpec("sip", "tcp")
    assert srv_query_name("Example.COM", spec) == "_sip._tcp.example.com"


def test_normalize_srv_spec_defaults_to_tcp() -> None:
    assert normalize_srv_spec(" SIP ") == SrvSpec("sip", "tcp")
    assert normalize_srv_spec("xmpp/tcp") == SrvSpec("xmpp", "tcp")
    assert normalize_srv_spec("sip/udp") == SrvSpec("sip", "udp")


def test_normalize_srv_spec_rejects_junk() -> None:
    with pytest.raises(SrvSpecError, match="empty"):
        normalize_srv_spec("  ")
    with pytest.raises(SrvSpecError, match="Invalid SRV service"):
        normalize_srv_spec("*.sip")
    with pytest.raises(SrvSpecError, match="Invalid SRV protocol"):
        normalize_srv_spec("sip/sctp")


def test_normalize_srv_specs_dedupes_and_caps() -> None:
    assert normalize_srv_specs(["sip", "SIP", "xmpp/udp"]) == (
        SrvSpec("sip", "tcp"),
        SrvSpec("xmpp", "udp"),
    )
    too_many = [f"svc{i}" for i in range(MAX_SRV + 1)]
    with pytest.raises(SrvSpecError, match="Too many"):
        normalize_srv_specs(too_many)


def test_srv_not_detected() -> None:
    observation = evaluate_srv("_sip._tcp.example.com", SrvSpec("sip", "tcp"), [])
    assert observation.status == "NOT DETECTED"
    assert observation.records == ()


def test_srv_found_sorts_priority() -> None:
    low = DNSRecord("SRV", "_sip._tcp.example.com", "20 0 5060 b.example.com", 60, priority=20)
    high = DNSRecord("SRV", "_sip._tcp.example.com", "10 0 5060 a.example.com", 60, priority=10)
    observation = evaluate_srv(
        "_sip._tcp.example.com",
        SrvSpec("sip", "tcp"),
        [low, high],
    )
    assert observation.status == "FOUND"
    assert observation.records[0].priority == 10
    assert observation.records[1].priority == 20


def test_srv_dot_target_is_found() -> None:
    record = DNSRecord(
        "SRV",
        "_sip._tcp.example.com",
        "0 0 0 .",
        60,
        priority=0,
        details=(("Note", "Target '.' means this service is not offered (RFC 2782)."),),
    )
    observation = evaluate_srv("_sip._tcp.example.com", SrvSpec("sip", "tcp"), [record])
    assert observation.status == "FOUND"
    assert observation.records[0].value.endswith(".")


def test_inspect_srv_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._client = MagicMock()
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()

    observation = resolver.inspect_srv("example.com", SrvSpec("sip", "tcp"))

    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "_sip._tcp.example.com"


def test_inspect_srv_timeout_is_not_detected_with_error() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_srv = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]

    observation = resolver.inspect_srv("example.com", SrvSpec("sip", "udp"))

    assert observation.status == "NOT DETECTED"
    assert observation.error is not None
    resolver.resolve_srv.assert_called_once_with("_sip._udp.example.com")


def test_inspect_srv_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_srv = MagicMock(return_value=_srv())  # type: ignore[method-assign]
    observation = resolver.inspect_srv("example.com", SrvSpec("sip", "tcp"))
    assert observation.status == "FOUND"
    resolver.resolve_srv.assert_called_once_with("_sip._tcp.example.com")
