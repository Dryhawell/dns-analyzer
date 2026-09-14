"""NAPTR rewrite listing for a caller-supplied name (RFC 3403 / 2915).

NAPTR publishes order, preference, flags, services, regexp, and a
replacement name. This tool only lists those fields. It does not apply
the regexp, does not follow the replacement to SRV/A/AAAA, and does not
guess ENUM, SIP, or other applications.

Missing NAPTR is common and is not a compromise. Default scans do not
query NAPTR; pass --naptr.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord

MAX_NAPTR = 8

_VALUE_RE = re.compile(
    r'^(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"\s+(\S+)\s*$'
)
_FLAG_MEANING = {
    "s": "next lookup is SRV (this tool does not follow it)",
    "a": "next lookup is A/AAAA (this tool does not follow it)",
    "u": "terminal; apply regexp (this tool does not rewrite)",
    "p": "protocol-specific (this tool does not interpret it)",
}

NAPTR_NOTE = (
    "NAPTR (RFC 3403) lists rewrite rules at this name. "
    "This tool does not apply the regexp, does not follow the replacement, "
    "and does not guess ENUM or SIP applications. "
    "A missing NAPTR is not a compromise. "
    "Flags S/A/U/P are labels only; they are not extra DNS or HTTP lookups."
)


@dataclass(frozen=True)
class NaptrRewrite:
    order: int
    preference: int
    flags: str
    flags_meaning: str
    services: str
    regexp: str
    replacement: str


@dataclass(frozen=True)
class NaptrObservation:
    status: str
    query_name: str
    rewrites: tuple[NaptrRewrite, ...]
    truncated: bool = False
    note: str = NAPTR_NOTE
    error: str | None = None


def flags_meaning(flags: str) -> str:
    if not flags:
        return "no flags"
    parts: list[str] = []
    seen: set[str] = set()
    for char in flags:
        key = char.lower()
        if key in seen:
            continue
        seen.add(key)
        parts.append(_FLAG_MEANING.get(key, f"unknown flag {char}"))
    return "; ".join(parts)


def rewrite_from_record(record: DNSRecord) -> NaptrRewrite | None:
    """Parse one NAPTR row. The regexp is stored, never executed."""
    match = _VALUE_RE.match(record.value)
    if match:
        order = int(match.group(1))
        preference = int(match.group(2))
        flags = match.group(3)
        services = match.group(4)
        regexp = match.group(5)
        replacement = match.group(6)
    else:
        parts = record.value.split(None, 5)
        if len(parts) < 6:
            return None
        try:
            order = int(parts[0])
            preference = int(parts[1])
        except ValueError:
            return None
        flags = parts[2].strip('"')
        services = parts[3].strip('"')
        regexp = parts[4].strip('"')
        replacement = parts[5]
    replacement = replacement.rstrip(".") or "."
    return NaptrRewrite(
        order=order,
        preference=preference,
        flags=flags,
        flags_meaning=flags_meaning(flags),
        services=services,
        regexp=regexp,
        replacement=replacement,
    )


def evaluate_naptr(
    query_name: str,
    records: Sequence[DNSRecord],
    error: str | None = None,
    limit: int = MAX_NAPTR,
) -> NaptrObservation:
    """Map published NAPTR records to FOUND / NOT DETECTED. No rewrite."""
    parsed: list[NaptrRewrite] = []
    for record in records:
        item = rewrite_from_record(record)
        if item is None:
            continue
        parsed.append(item)
    parsed.sort(
        key=lambda item: (
            item.order,
            item.preference,
            item.services,
            item.replacement,
        )
    )
    truncated = len(parsed) > limit
    rewrites = tuple(parsed[:limit])
    host = query_name.rstrip(".").lower()
    if not rewrites:
        return NaptrObservation(
            status="NOT DETECTED",
            query_name=host,
            rewrites=(),
            truncated=False,
            error=error,
        )
    return NaptrObservation(
        status="FOUND",
        query_name=host,
        rewrites=rewrites,
        truncated=truncated,
        error=error,
    )
