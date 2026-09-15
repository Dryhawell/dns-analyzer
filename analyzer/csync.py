"""CSYNC listing (RFC 7477). Child-to-parent NS/A/AAAA signaling.

CSYNC at the child apex tells a parent which record types to copy
(typically NS, and A/AAAA glue). This tool only lists what this resolver
sees.

It does not contact the parent registry, does not compare CSYNC to the
child NS set, and does not update parent delegation.

NOT DETECTED is common. Many zones never publish CSYNC. Absence is not
broken DNS and is not a compromise.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

MAX_CSYNC_ITEMS = 8
MAX_CSYNC_TYPES = 16

IMMEDIATE_FLAG = 0x0001
SOA_MINIMUM_FLAG = 0x0002

CSYNC_NOTE = (
    "CSYNC (RFC 7477) signals which record types a parent may copy from "
    "the child (often NS and A/AAAA glue). This tool lists records visible "
    "to this resolver. It does not contact the parent registry, does not "
    "compare CSYNC to the child NS set, and does not update parent "
    "delegation. NOT DETECTED is common; many zones never publish CSYNC. "
    "Absence is not broken DNS and is not a compromise. "
    "The serial is a change counter for the parent, not a security score."
)


@dataclass(frozen=True)
class CsyncRecord:
    serial: int
    flags: int
    immediate: bool
    soa_minimum: bool
    types: tuple[str, ...]
    types_truncated: bool = False


@dataclass(frozen=True)
class CsyncObservation:
    status: str
    query_name: str
    csync: tuple[CsyncRecord, ...] = ()
    truncated: bool = False
    note: str = CSYNC_NOTE
    error: str | None = None


def evaluate_csync(
    query_name: str,
    *,
    found: bool,
    csync: Sequence[CsyncRecord] = (),
    truncated: bool = False,
    error: str | None = None,
) -> CsyncObservation:
    """Map published CSYNC to FOUND / NOT DETECTED / UNREADABLE."""
    if found:
        status = "FOUND"
    elif error:
        status = "UNREADABLE"
    else:
        status = "NOT DETECTED"
    return CsyncObservation(
        status=status,
        query_name=query_name,
        csync=tuple(csync),
        truncated=truncated,
        error=error,
    )


def parse_csync(
    rdatas: Sequence[object],
    limit: int = MAX_CSYNC_ITEMS,
) -> tuple[tuple[CsyncRecord, ...], bool]:
    parsed: list[CsyncRecord] = []
    for rdata in rdatas:
        flags = int(getattr(rdata, "flags", 0) or 0)
        types, types_truncated = _csync_types(rdata)
        parsed.append(
            CsyncRecord(
                serial=int(getattr(rdata, "serial", 0) or 0),
                flags=flags,
                immediate=bool(flags & IMMEDIATE_FLAG),
                soa_minimum=bool(flags & SOA_MINIMUM_FLAG),
                types=types,
                types_truncated=types_truncated,
            )
        )
    truncated = len(parsed) > limit
    return tuple(parsed[:limit]), truncated


def _csync_types(rdata: object) -> tuple[tuple[str, ...], bool]:
    explicit = getattr(rdata, "types", None)
    if explicit is not None:
        names = tuple(str(item) for item in explicit)
        truncated = len(names) > MAX_CSYNC_TYPES
        return names[:MAX_CSYNC_TYPES], truncated
    to_text = getattr(rdata, "to_text", None)
    if callable(to_text):
        tokens = to_text().split()
        names = tuple(token for token in tokens[2:] if token)
        truncated = len(names) > MAX_CSYNC_TYPES
        return names[:MAX_CSYNC_TYPES], truncated
    return (), False
