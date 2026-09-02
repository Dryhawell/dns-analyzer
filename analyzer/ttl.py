"""TTL is a cache lifetime, not a security score.

A resolver (and often the OS) may reuse an answer until TTL seconds pass.
Low TTL → changes become visible sooner (faster "propagation"), more queries.
High TTL → fewer queries, stale answers last longer after a record changes.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord


@dataclass(frozen=True)
class TtlObservation:
    shortest: int
    longest: int
    shortest_types: tuple[str, ...]
    longest_types: tuple[str, ...]
    record_count: int


def format_duration(seconds: int) -> str:
    """Human-readable span next to the raw TTL (seconds)."""
    if seconds < 0:
        seconds = 0
    if seconds < 60:
        return f"{seconds}s"
    minutes, rem_s = divmod(seconds, 60)
    if seconds < 3600:
        if rem_s:
            return f"{seconds}s (~{minutes}m)"
        return f"{seconds}s ({minutes}m)"
    hours, rem_m = divmod(seconds, 3600)
    if seconds < 86400:
        if rem_m:
            return f"{seconds}s (~{hours}h)"
        return f"{seconds}s ({hours}h)"
    days, rem_h = divmod(seconds, 86400)
    if rem_h:
        return f"{seconds}s (~{days}d)"
    return f"{seconds}s ({days}d)"


def describe_cache(seconds: int) -> str:
    """Observational cache bucket. Never 'secure' or 'insecure'."""
    if seconds < 60:
        return "very short cache — changes can show up quickly"
    if seconds < 300:
        return "short cache"
    if seconds <= 3600:
        return "moderate cache"
    if seconds <= 86400:
        return "long cache — fewer resolver queries"
    return "very long cache — updates may take a day or more to spread"


def summarize_ttls(records: Sequence[DNSRecord]) -> TtlObservation | None:
    valid = [item for item in records if item.ttl >= 0]
    if not valid:
        return None

    shortest = min(item.ttl for item in valid)
    longest = max(item.ttl for item in valid)
    short_types = tuple(sorted({item.record_type for item in valid if item.ttl == shortest}))
    long_types = tuple(sorted({item.record_type for item in valid if item.ttl == longest}))
    return TtlObservation(
        shortest=shortest,
        longest=longest,
        shortest_types=short_types,
        longest_types=long_types,
        record_count=len(valid),
    )


def format_ttl_line(seconds: int) -> str:
    return f"TTL: {format_duration(seconds)}"
