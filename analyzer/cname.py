"""CNAME target address lookup. HTTP is not fetched.

A CNAME is an alias: this name is published as another name. Clients still
need A/AAAA at the end of that chain. This tool only reads DNS. It does not
open TCP/80 or TCP/443, and a missing target is not proof of takeover.

Apex names often have no CNAME (they already have SOA/NS). A loop or a
name without addresses is an observation, not a compromise.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord

MAX_TARGETS = 8
MAX_HOPS = 5

CNAME_TARGET_NOTE = (
    "CNAME names another host; clients still need A/AAAA at the end of the "
    "chain. This tool does not fetch HTTP or prove subdomain takeover. "
    "NXDOMAIN or no address can be a leftover alias, IPv6-only miss, or "
    "timeout. Apex names often have no CNAME. A loop is a configuration "
    "error, not hijacking."
)


@dataclass(frozen=True)
class CnameTargetCheck:
    target: str
    chain: tuple[str, ...]
    ipv4: tuple[str, ...]
    ipv6: tuple[str, ...]
    status: str
    error: str | None = None


@dataclass(frozen=True)
class CnameTargetObservation:
    status: str
    checks: tuple[CnameTargetCheck, ...]
    truncated: bool = False
    note: str = CNAME_TARGET_NOTE
    error: str | None = None


def cname_target_name(value: str) -> str:
    return value.strip().rstrip(".").lower()


def unique_cname_targets(records: Sequence[DNSRecord]) -> tuple[str, ...]:
    """Preserve first-seen order; skip empty names."""
    seen: list[str] = []
    for record in records:
        host = cname_target_name(record.value)
        if not host or host in seen:
            continue
        seen.append(host)
    return tuple(seen)


def evaluate_cname_targets(
    checks: Sequence[CnameTargetCheck],
    truncated: bool = False,
    error: str | None = None,
) -> CnameTargetObservation:
    if error and not checks:
        return CnameTargetObservation(
            status="UNREADABLE",
            checks=(),
            truncated=truncated,
            error=error,
        )
    if not checks:
        return CnameTargetObservation(
            status="NOT DETECTED",
            checks=(),
            truncated=truncated,
            error=error,
        )
    return CnameTargetObservation(
        status="FOUND",
        checks=tuple(checks),
        truncated=truncated,
        error=error,
    )
