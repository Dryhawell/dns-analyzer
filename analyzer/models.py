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
    details: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class CoreLookup:
    """A, AAAA, CNAME, MX, NS, TXT, SOA and CAA for one name."""

    a: tuple[DNSRecord, ...]
    aaaa: tuple[DNSRecord, ...]
    cname: tuple[DNSRecord, ...]
    mx: tuple[DNSRecord, ...]
    ns: tuple[DNSRecord, ...]
    txt: tuple[DNSRecord, ...]
    soa: tuple[DNSRecord, ...]
    caa: tuple[DNSRecord, ...]
    errors: tuple[tuple[str, str], ...] = ()

    def all_records(self) -> tuple[DNSRecord, ...]:
        return (
            self.a
            + self.aaaa
            + self.cname
            + self.mx
            + self.ns
            + self.txt
            + self.soa
            + self.caa
        )
