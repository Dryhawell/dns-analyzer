"""Dataclass models for DNS records and later analysis results."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DNSRecord:
    """One resource record from a DNS response.

    TTL is stored as returned by the resolver. It is not a security score.
    """

    record_type: str
    name: str
    value: str
    ttl: int
