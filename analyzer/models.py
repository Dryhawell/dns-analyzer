"""Dataclass models for DNS records and later analysis results."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DNSRecord:
    """One resource record from a DNS response.

    TTL is stored as returned by the resolver. It is not a security score.
    priority is set for MX (lower number = higher mail priority).
    """

    record_type: str
    name: str
    value: str
    ttl: int
    priority: int | None = None


@dataclass(frozen=True)
class CoreLookup:
    """A, AAAA, CNAME, MX and NS for one name (Phase 5)."""

    a: tuple[DNSRecord, ...]
    aaaa: tuple[DNSRecord, ...]
    cname: tuple[DNSRecord, ...]
    mx: tuple[DNSRecord, ...]
    ns: tuple[DNSRecord, ...]
