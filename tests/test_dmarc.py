"""DMARC parsing tests. No network access."""

from unittest.mock import MagicMock

import dns.resolver

from analyzer.dmarc import dmarc_query_name, evaluate_dmarc
from analyzer.exceptions import DNSTimeoutError
from analyzer.models import DNSRecord
from analyzer.resolver import DNSResolver


def _txt(value: str) -> list[DNSRecord]:
    return [DNSRecord("TXT", "_dmarc.example.com", value, 300)]


def test_dmarc_query_name() -> None:
    assert dmarc_query_name("Example.COM") == "_dmarc.example.com"


def test_dmarc_not_detected() -> None:
    observation = evaluate_dmarc("_dmarc.example.com", [])
    assert observation.status == "NOT DETECTED"
    assert observation.policy is None


def test_dmarc_reject() -> None:
    observation = evaluate_dmarc(
        "_dmarc.example.com",
        _txt("v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"),
    )
    assert observation.status == "FOUND"
    assert observation.policy == "reject"
    assert "reject" in (observation.policy_meaning or "")
    assert observation.rua == "mailto:dmarc@example.com"
    assert observation.pct == "100"


def test_dmarc_none_is_monitor_only() -> None:
    observation = evaluate_dmarc(
        "_dmarc.example.com",
        _txt("v=DMARC1; p=none"),
    )
    assert observation.policy == "none"
    assert "monitor" in (observation.policy_meaning or "")


def test_dmarc_quarantine() -> None:
    observation = evaluate_dmarc(
        "_dmarc.example.com",
        _txt("v=DMARC1; p=quarantine; sp=none"),
    )
    assert observation.policy == "quarantine"
    assert observation.subdomain_policy == "none"


def test_inspect_dmarc_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._client = MagicMock()
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()

    observation = resolver.inspect_dmarc("example.com")

    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "_dmarc.example.com"


def test_inspect_dmarc_timeout_is_not_detected_with_error() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._client = MagicMock()
    resolver._client.resolve.side_effect = DNSTimeoutError()

    # resolve_txt wraps Timeout as DNSTimeoutError via _query; simulate that
    resolver.resolve_txt = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]

    observation = resolver.inspect_dmarc("example.com")

    assert observation.status == "NOT DETECTED"
    assert observation.error is not None


def test_inspect_dmarc_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_txt = MagicMock(  # type: ignore[method-assign]
        return_value=_txt("v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com")
    )
    observation = resolver.inspect_dmarc("example.com")
    assert observation.status == "FOUND"
    assert observation.policy == "quarantine"
    resolver.resolve_txt.assert_called_once_with("_dmarc.example.com")


def test_multiple_dmarc_records() -> None:
    observation = evaluate_dmarc(
        "_dmarc.example.com",
        _txt("v=DMARC1; p=none") + _txt("v=DMARC1; p=reject"),
    )
    assert observation.status == "FOUND"
    assert observation.multiple_records is True
    assert observation.policy == "none"
