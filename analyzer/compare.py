"""Compare A/AAAA answers from more than one recursive resolver.

Different answers are a signal (geo-DNS, anycast, cache lag, split-horizon,
or a lying resolver). They are not proof of hijacking or compromise.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import CoreLookup

COMPARE_TYPES = ("A", "AAAA")
COMPARISON_NOTE = (
    "Different answers can be geo-DNS, anycast, cache lag, or split-horizon. "
    "This is not proof of DNS hijacking or compromise."
)


@dataclass(frozen=True)
class ResolverSnapshot:
    name: str
    nameservers: tuple[str, ...]
    answers: dict[str, tuple[str, ...]]
    error: str | None = None


@dataclass(frozen=True)
class ResolverComparison:
    primary: str
    snapshots: tuple[ResolverSnapshot, ...]
    status: str
    inconsistent_types: tuple[str, ...]
    note: str = COMPARISON_NOTE


def types_for_comparison(needed: Sequence[str] | None) -> tuple[str, ...]:
    """Compare address types that the primary lookup actually queried."""
    if needed is None:
        return COMPARE_TYPES
    wanted = {str(label).upper() for label in needed}
    return tuple(label for label in COMPARE_TYPES if label in wanted)


def snapshot_from_lookup(
    name: str,
    lookup: CoreLookup,
    types: Sequence[str],
    nameservers: tuple[str, ...] = (),
    error: str | None = None,
) -> ResolverSnapshot:
    buckets = {"A": lookup.a, "AAAA": lookup.aaaa}
    answers = {
        label: tuple(sorted({record.value for record in buckets.get(label, ())}))
        for label in types
    }
    return ResolverSnapshot(
        name=name,
        nameservers=nameservers,
        answers=answers,
        error=error,
    )


def empty_snapshot(
    name: str,
    types: Sequence[str],
    nameservers: tuple[str, ...] = (),
    error: str | None = None,
) -> ResolverSnapshot:
    return ResolverSnapshot(
        name=name,
        nameservers=nameservers,
        answers={label: () for label in types},
        error=error,
    )


def compare_snapshots(
    snapshots: Sequence[ResolverSnapshot],
    types: Sequence[str] = COMPARE_TYPES,
) -> ResolverComparison:
    if not snapshots:
        raise ValueError("Need at least one resolver snapshot.")
    usable = [item for item in snapshots if item.error is None]
    inconsistent: list[str] = []
    if len(usable) >= 2:
        for label in types:
            values = {item.answers.get(label, ()) for item in usable}
            if len(values) > 1:
                inconsistent.append(label)
        status = "INCONSISTENT" if inconsistent else "CONSISTENT"
    else:
        status = "INCOMPLETE"

    return ResolverComparison(
        primary=snapshots[0].name,
        snapshots=tuple(snapshots),
        status=status,
        inconsistent_types=tuple(inconsistent),
        note=COMPARISON_NOTE,
    )
