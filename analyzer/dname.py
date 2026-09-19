"""DNAME listing for a caller-supplied name (RFC 6672).

DNAME redirects an entire subtree to another suffix. This tool only lists
the target at the queried name. It does not synthesize CNAME records for
names under this node, does not walk the subtree, and does not fetch HTTP.

Missing DNAME is common and is not a compromise. Default scans do not
query DNAME; pass --dname.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord

MAX_DNAME = 8

DNAME_NOTE = (
    "DNAME (RFC 6672) redirects a whole subtree to another suffix. "
    "This tool lists the target at this name. It does not synthesize "
    "CNAME records for names under this node, does not walk the subtree, "
    "and does not fetch HTTP. A missing DNAME is not a compromise. "
    "A published target is a DNS suffix, not a site this tool visited."
)


@dataclass(frozen=True)
class DnameTarget:
    target: str


@dataclass(frozen=True)
class DnameObservation:
    status: str
    query_name: str
    dnames: tuple[DnameTarget, ...]
    truncated: bool = False
    note: str = DNAME_NOTE
    error: str | None = None


def target_from_record(record: DNSRecord) -> DnameTarget | None:
    """Parse one DNAME row. The target is stored, never followed."""
    target = record.value.strip().rstrip(".").lower()
    if not target:
        return None
    return DnameTarget(target=target)


def evaluate_dname(
    query_name: str,
    records: Sequence[DNSRecord],
    error: str | None = None,
    limit: int = MAX_DNAME,
) -> DnameObservation:
    """Map published DNAME records to FOUND / NOT DETECTED. No subtree walk."""
    parsed: list[DnameTarget] = []
    seen: set[str] = set()
    for record in records:
        item = target_from_record(record)
        if item is None or item.target in seen:
            continue
        seen.add(item.target)
        parsed.append(item)
    truncated = len(parsed) > limit
    dnames = tuple(parsed[:limit])
    host = query_name.rstrip(".").lower()
    if not dnames:
        return DnameObservation(
            status="NOT DETECTED",
            query_name=host,
            dnames=(),
            truncated=False,
            error=error,
        )
    return DnameObservation(
        status="FOUND",
        query_name=host,
        dnames=dnames,
        truncated=truncated,
        error=error,
    )
