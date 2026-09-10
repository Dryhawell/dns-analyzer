"""MX host address lookup. SMTP is not probed.

MX names a mail exchanger. Delivery still needs A/AAAA of that host.
This tool only reads DNS. It does not open TCP/25.

RFC 7505 null MX (exchange ".") means the name does not accept mail.
Missing MX is common for names that are not mail domains.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord

MAX_HOSTS = 8

MX_HOST_NOTE = (
    "MX names a mail host; delivery still needs A/AAAA of that host. "
    "This tool does not open TCP/25 or speak SMTP. Missing MX is common "
    "for names that are not mail domains. Null MX (.) means mail is "
    "not accepted here (RFC 7505). A missing address is not a compromise."
)


@dataclass(frozen=True)
class MxHostCheck:
    host: str
    preference: int | None
    ipv4: tuple[str, ...]
    ipv6: tuple[str, ...]
    status: str
    error: str | None = None


@dataclass(frozen=True)
class MxHostObservation:
    status: str
    query_name: str
    checks: tuple[MxHostCheck, ...]
    truncated: bool = False
    note: str = MX_HOST_NOTE
    error: str | None = None


def mx_host_name(value: str) -> str:
    """Normalize an MX exchange. Empty / '.' is the RFC 7505 null MX."""
    name = value.strip().rstrip(".").lower()
    if name in {"", "."}:
        return "."
    return name


def unique_mx_hosts(records: Sequence[DNSRecord]) -> tuple[tuple[str, int | None], ...]:
    """Lowest preference first; duplicate hosts keep the first (best) preference."""
    ordered = sorted(
        records,
        key=lambda item: (
            item.priority is None,
            item.priority if item.priority is not None else 0,
        ),
    )
    seen: list[str] = []
    result: list[tuple[str, int | None]] = []
    for record in ordered:
        host = mx_host_name(record.value)
        if host in seen:
            continue
        seen.append(host)
        result.append((host, record.priority))
    return tuple(result)


def evaluate_mx_hosts(
    query_name: str,
    checks: Sequence[MxHostCheck],
    truncated: bool = False,
    error: str | None = None,
) -> MxHostObservation:
    if error and not checks:
        return MxHostObservation(
            status="UNREADABLE",
            query_name=query_name,
            checks=(),
            truncated=truncated,
            error=error,
        )
    if not checks:
        return MxHostObservation(
            status="NOT DETECTED",
            query_name=query_name,
            checks=(),
            truncated=truncated,
            error=error,
        )
    return MxHostObservation(
        status="FOUND",
        query_name=query_name,
        checks=tuple(checks),
        truncated=truncated,
        error=error,
    )
