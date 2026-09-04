"""Resolver comparison. No network access."""

from analyzer.compare import (
    COMPARISON_NOTE,
    compare_snapshots,
    empty_snapshot,
    snapshot_from_lookup,
    types_for_comparison,
)
from analyzer.models import CoreLookup, DNSRecord


def _lookup(*values: str, v6: tuple[str, ...] = ()) -> CoreLookup:
    return CoreLookup(
        a=tuple(DNSRecord("A", "example.com", value, 60) for value in values),
        aaaa=tuple(DNSRecord("AAAA", "example.com", value, 60) for value in v6),
        cname=(),
        mx=(),
        ns=(),
        txt=(),
        soa=(),
        caa=(),
    )


def test_types_for_comparison_default_is_addresses() -> None:
    assert types_for_comparison(None) == ("A", "AAAA")
    assert types_for_comparison(("A", "MX")) == ("A",)
    assert types_for_comparison(("A", "AAAA", "CNAME", "TXT", "CAA")) == ("A", "AAAA")


def test_consistent_a_records() -> None:
    types = ("A",)
    left = snapshot_from_lookup("system", _lookup("93.184.216.34"), types)
    right = snapshot_from_lookup("secondary", _lookup("93.184.216.34"), types)
    result = compare_snapshots((left, right), types)
    assert result.status == "CONSISTENT"
    assert result.inconsistent_types == ()
    assert "hijacking" in result.note.lower()


def test_inconsistent_a_records() -> None:
    types = ("A",)
    left = snapshot_from_lookup("system", _lookup("93.184.216.34"), types)
    right = snapshot_from_lookup("secondary", _lookup("198.51.100.10"), types)
    result = compare_snapshots((left, right), types)
    assert result.status == "INCONSISTENT"
    assert result.inconsistent_types == ("A",)
    assert result.primary == "system"
    assert COMPARISON_NOTE == result.note


def test_order_of_answers_does_not_matter() -> None:
    types = ("A",)
    left = snapshot_from_lookup("a", _lookup("1.2.3.4", "5.6.7.8"), types)
    right = snapshot_from_lookup("b", _lookup("5.6.7.8", "1.2.3.4"), types)
    assert compare_snapshots((left, right), types).status == "CONSISTENT"


def test_extra_resolver_error_is_incomplete() -> None:
    types = ("A",)
    left = snapshot_from_lookup("system", _lookup("93.184.216.34"), types)
    right = empty_snapshot("secondary", types, error="DNS query timed out.")
    result = compare_snapshots((left, right), types)
    assert result.status == "INCOMPLETE"
    assert result.inconsistent_types == ()
    assert result.snapshots[1].error == "DNS query timed out."
