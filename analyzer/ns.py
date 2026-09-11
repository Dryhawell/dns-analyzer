"""NS host address lookup. Zone transfer is not attempted.

NS names an authoritative server. Resolvers still need A/AAAA of that host.
This tool only reads DNS via the recursive resolver. It does not open
TCP/53 to the NS, does not send AXFR/IXFR, and does not test lameness.

An NS inside the zone (in-bailiwick) normally needs glue at the parent.
An NS in another zone (out-of-bailiwick) is looked up like any other name.
Missing NS is common on subdomains; the parent holds the delegation.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord

MAX_HOSTS = 8

NS_HOST_NOTE = (
    "NS names an authoritative server; resolvers still need A/AAAA of that "
    "host. This tool does not open TCP/53 to the NS or attempt AXFR. "
    "In-bailiwick NS names usually need glue at the parent. Missing NS on "
    "a subdomain is common. A missing address is not a compromise, and it "
    "is not proof of a lame nameserver."
)


@dataclass(frozen=True)
class NsHostCheck:
    host: str
    in_bailiwick: bool
    ipv4: tuple[str, ...]
    ipv6: tuple[str, ...]
    status: str
    error: str | None = None


@dataclass(frozen=True)
class NsHostObservation:
    status: str
    query_name: str
    checks: tuple[NsHostCheck, ...]
    truncated: bool = False
    note: str = NS_HOST_NOTE
    error: str | None = None


def ns_host_name(value: str) -> str:
    """Normalize an NS hostname. Empty is not a usable nameserver."""
    return value.strip().rstrip(".").lower()


def ns_in_bailiwick(zone: str, ns_host: str) -> bool:
    """True when the NS name is the zone or a descendant of it."""
    zone_name = zone.strip().rstrip(".").lower()
    host = ns_host_name(ns_host)
    if not zone_name or not host:
        return False
    return host == zone_name or host.endswith("." + zone_name)


def unique_ns_hosts(records: Sequence[DNSRecord]) -> tuple[str, ...]:
    """Preserve first-seen order; skip empty names."""
    seen: list[str] = []
    for record in records:
        host = ns_host_name(record.value)
        if not host or host in seen:
            continue
        seen.append(host)
    return tuple(seen)


def evaluate_ns_hosts(
    query_name: str,
    checks: Sequence[NsHostCheck],
    truncated: bool = False,
    error: str | None = None,
) -> NsHostObservation:
    if error and not checks:
        return NsHostObservation(
            status="UNREADABLE",
            query_name=query_name,
            checks=(),
            truncated=truncated,
            error=error,
        )
    if not checks:
        return NsHostObservation(
            status="NOT DETECTED",
            query_name=query_name,
            checks=(),
            truncated=truncated,
            error=error,
        )
    return NsHostObservation(
        status="FOUND",
        query_name=query_name,
        checks=tuple(checks),
        truncated=truncated,
        error=error,
    )
