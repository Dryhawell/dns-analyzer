"""NAPTR rewrite listing tests. No network access. Regexp is never executed."""

from unittest.mock import MagicMock

import dns.resolver

from analyzer.exceptions import DNSTimeoutError
from analyzer.models import DNSRecord
from analyzer.resolver import DNSResolver
from analyzer.naptr import (
    MAX_NAPTR,
    evaluate_naptr,
    flags_meaning,
    rewrite_from_record,
)


def _naptr(
    value: str = '100 50 "u" "E2U+sip" "!^.*$!sip:info@example.com!" .',
    name: str = "example.com",
) -> list[DNSRecord]:
    return [DNSRecord("NAPTR", name, value, 300)]


def test_flags_meaning() -> None:
    assert flags_meaning("") == "no flags"
    assert "does not rewrite" in flags_meaning("u")
    assert "SRV" in flags_meaning("S")
    assert "unknown flag x" in flags_meaning("x")


def test_naptr_not_detected() -> None:
    observation = evaluate_naptr("Example.COM", [])
    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "example.com"
    assert observation.rewrites == ()


def test_naptr_found_sorts_order_then_preference() -> None:
    low = DNSRecord(
        "NAPTR",
        "example.com",
        '200 10 "u" "E2U+sip" "!^.*$!sip:b@example.com!" .',
        60,
    )
    high = DNSRecord(
        "NAPTR",
        "example.com",
        '100 50 "u" "E2U+sip" "!^.*$!sip:a@example.com!" sip.example.com.',
        60,
    )
    same_order = DNSRecord(
        "NAPTR",
        "example.com",
        '100 10 "s" "SIP+D2T" "" _sip._tcp.example.com.',
        60,
    )
    observation = evaluate_naptr("example.com", [low, high, same_order])
    assert observation.status == "FOUND"
    assert observation.rewrites[0].order == 100
    assert observation.rewrites[0].preference == 10
    assert observation.rewrites[0].flags == "s"
    assert observation.rewrites[0].replacement == "_sip._tcp.example.com"
    assert observation.rewrites[1].order == 100
    assert observation.rewrites[1].preference == 50
    assert observation.rewrites[1].replacement == "sip.example.com"
    assert observation.rewrites[2].order == 200
    assert observation.rewrites[2].replacement == "."


def test_naptr_does_not_execute_regexp() -> None:
    record = DNSRecord(
        "NAPTR",
        "example.com",
        '10 10 "u" "E2U+sip" "!^.*$!sip:rewritten@example.com!" .',
        60,
    )
    observation = evaluate_naptr("example.com", [record])
    assert observation.rewrites[0].regexp == "!^.*$!sip:rewritten@example.com!"
    assert "does not apply the regexp" in observation.note


def test_naptr_caps_at_eight() -> None:
    records = [
        DNSRecord(
            "NAPTR",
            "example.com",
            f'{i} 0 "u" "E2U+sip" "" .',
            60,
        )
        for i in range(MAX_NAPTR + 2)
    ]
    observation = evaluate_naptr("example.com", records)
    assert len(observation.rewrites) == MAX_NAPTR
    assert observation.truncated is True


def test_rewrite_from_record_fallback_split() -> None:
    record = DNSRecord(
        "NAPTR",
        "example.com",
        "10 20 a SIP+D2U empty sip.example.com.",
        60,
    )
    item = rewrite_from_record(record)
    assert item is not None
    assert item.order == 10
    assert item.preference == 20
    assert item.flags == "a"
    assert item.replacement == "sip.example.com"


def test_inspect_naptr_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._client = MagicMock()
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()

    observation = resolver.inspect_naptr("example.com")

    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "example.com"


def test_inspect_naptr_timeout_is_not_detected_with_error() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_naptr = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]

    observation = resolver.inspect_naptr("Example.COM.")

    assert observation.status == "NOT DETECTED"
    assert observation.error is not None
    resolver.resolve_naptr.assert_called_once_with("example.com")


def test_inspect_naptr_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_naptr = MagicMock(return_value=_naptr())  # type: ignore[method-assign]
    observation = resolver.inspect_naptr("example.com")
    assert observation.status == "FOUND"
    assert observation.rewrites[0].services == "E2U+sip"
    resolver.resolve_naptr.assert_called_once_with("example.com")
