"""MTA-STS TXT parsing tests. No network access."""

from unittest.mock import MagicMock

import dns.resolver

from analyzer.exceptions import DNSTimeoutError
from analyzer.models import DNSRecord
from analyzer.mtasts import (
    evaluate_mta_sts,
    mta_sts_policy_host,
    mta_sts_query_name,
)
from analyzer.resolver import DNSResolver


def _txt(value: str) -> list[DNSRecord]:
    return [DNSRecord("TXT", "_mta-sts.example.com", value, 300)]


def test_mta_sts_query_names() -> None:
    assert mta_sts_query_name("Example.COM") == "_mta-sts.example.com"
    assert mta_sts_policy_host("Example.COM") == "mta-sts.example.com"


def test_mta_sts_not_detected() -> None:
    observation = evaluate_mta_sts("_mta-sts.example.com", "mta-sts.example.com", [])
    assert observation.status == "NOT DETECTED"
    assert observation.policy_id is None


def test_mta_sts_found() -> None:
    observation = evaluate_mta_sts(
        "_mta-sts.example.com",
        "mta-sts.example.com",
        _txt("v=STSv1; id=20160831085700Z"),
    )
    assert observation.status == "FOUND"
    assert observation.policy_id == "20160831085700Z"


def test_mta_sts_requires_semicolon_after_version() -> None:
    observation = evaluate_mta_sts(
        "_mta-sts.example.com",
        "mta-sts.example.com",
        _txt("v=STSv1 id=abc"),
    )
    assert observation.status == "NOT DETECTED"


def test_mta_sts_found_without_id() -> None:
    observation = evaluate_mta_sts(
        "_mta-sts.example.com",
        "mta-sts.example.com",
        _txt("v=STSv1;"),
    )
    assert observation.status == "FOUND"
    assert observation.policy_id is None


def test_multiple_mta_sts_records() -> None:
    observation = evaluate_mta_sts(
        "_mta-sts.example.com",
        "mta-sts.example.com",
        _txt("v=STSv1; id=one") + _txt("v=STSv1; id=two"),
    )
    assert observation.multiple_records is True
    assert observation.policy_id == "one"


def test_inspect_mta_sts_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._client = MagicMock()
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()

    observation = resolver.inspect_mta_sts("example.com")

    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "_mta-sts.example.com"
    assert observation.policy_host == "mta-sts.example.com"


def test_inspect_mta_sts_timeout_has_error() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_txt = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]

    observation = resolver.inspect_mta_sts("example.com")

    assert observation.status == "NOT DETECTED"
    assert observation.error is not None


def test_inspect_mta_sts_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_txt = MagicMock(  # type: ignore[method-assign]
        return_value=_txt("v=STSv1; id=abc")
    )
    observation = resolver.inspect_mta_sts("example.com")
    assert observation.status == "FOUND"
    assert observation.policy_id == "abc"
    resolver.resolve_txt.assert_called_once_with("_mta-sts.example.com")
