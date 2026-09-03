"""Aggregate result of one analysis run.

Kept out of models.py so DNSRecord stays free of security imports
(security.py already imports CoreLookup).
"""

from __future__ import annotations

from dataclasses import dataclass

from analyzer.dmarc import DmarcObservation
from analyzer.dnssec import DnssecObservation
from analyzer.models import DNSRecord
from analyzer.security import SecurityReport
from analyzer.spf import SpfObservation


@dataclass(frozen=True)
class DNSAnalysisResult:
    """One completed lookup, ready for CLI display or file export."""

    target: str
    mode: str
    scan_time: str
    duration_ms: int
    records: tuple[DNSRecord, ...]
    errors: tuple[tuple[str, str], ...] = ()
    dnssec: DnssecObservation | None = None
    spf: SpfObservation | None = None
    dmarc: DmarcObservation | None = None
    security: SecurityReport | None = None
    ptr_query: str | None = None
    view_record_types: tuple[str, ...] | None = None
    view_security: bool = True
