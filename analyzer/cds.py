"""CDS / CDNSKEY listing (RFC 7344). Child-to-parent DS signaling.

CDS and CDNSKEY are published at the child apex so a parent can update DS
without a registrar ticket. This tool only lists what this resolver sees.

It does not compare CDS to DS or DNSKEY, does not contact the parent
registry, and does not submit a DS update.

NOT DETECTED is common. Many signed zones never publish CDS. Absence is
not broken DNSSEC and is not a compromise.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.dnssec import (
    DnssecDelegation,
    DnssecKey,
    parse_delegations,
    parse_dnskeys,
)

MAX_CDS_ITEMS = 8

CDS_NOTE = (
    "CDS/CDNSKEY (RFC 7344) signal a DS change from the child to the parent. "
    "This tool lists records visible to this resolver. "
    "It does not check that CDS matches DNSKEY or DS, does not contact the "
    "parent registry, and does not submit a DS update. "
    "NOT DETECTED is common; many signed zones never publish CDS. "
    "Absence is not broken DNSSEC and is not a compromise."
)


@dataclass(frozen=True)
class CdsRecord:
    key_tag: int
    algorithm: int
    algorithm_meaning: str
    digest_type: int
    digest_meaning: str


@dataclass(frozen=True)
class CdnskeyRecord:
    flags: int
    protocol: int
    algorithm: int
    algorithm_meaning: str
    role: str
    zone_key: bool
    secure_entry_point: bool
    key_tag: int | None


@dataclass(frozen=True)
class CdsObservation:
    status: str
    query_name: str
    cds_found: bool
    cdnskey_found: bool
    cds: tuple[CdsRecord, ...] = ()
    cdnskey: tuple[CdnskeyRecord, ...] = ()
    cds_truncated: bool = False
    cdnskey_truncated: bool = False
    note: str = CDS_NOTE
    error: str | None = None


def evaluate_cds(
    query_name: str,
    *,
    cds_found: bool,
    cdnskey_found: bool,
    cds: Sequence[CdsRecord] = (),
    cdnskey: Sequence[CdnskeyRecord] = (),
    cds_truncated: bool = False,
    cdnskey_truncated: bool = False,
    error: str | None = None,
) -> CdsObservation:
    """Map published CDS/CDNSKEY to FOUND / NOT DETECTED / UNREADABLE."""
    found = cds_found or cdnskey_found
    if found:
        status = "FOUND"
    elif error:
        status = "UNREADABLE"
    else:
        status = "NOT DETECTED"
    return CdsObservation(
        status=status,
        query_name=query_name,
        cds_found=cds_found,
        cdnskey_found=cdnskey_found,
        cds=tuple(cds),
        cdnskey=tuple(cdnskey),
        cds_truncated=cds_truncated,
        cdnskey_truncated=cdnskey_truncated,
        error=error,
    )


def parse_cds(
    rdatas: Sequence[object],
    limit: int = MAX_CDS_ITEMS,
) -> tuple[tuple[CdsRecord, ...], bool]:
    parsed, truncated = parse_delegations(rdatas, limit)
    return tuple(_cds_record(item) for item in parsed), truncated


def parse_cdnskey(
    rdatas: Sequence[object],
    limit: int = MAX_CDS_ITEMS,
) -> tuple[tuple[CdnskeyRecord, ...], bool]:
    parsed, truncated = parse_dnskeys(rdatas, limit)
    return tuple(_cdnskey_record(item) for item in parsed), truncated


def _cds_record(item: DnssecDelegation) -> CdsRecord:
    return CdsRecord(
        key_tag=item.key_tag,
        algorithm=item.algorithm,
        algorithm_meaning=item.algorithm_meaning,
        digest_type=item.digest_type,
        digest_meaning=item.digest_meaning,
    )


def _cdnskey_record(item: DnssecKey) -> CdnskeyRecord:
    return CdnskeyRecord(
        flags=item.flags,
        protocol=item.protocol,
        algorithm=item.algorithm,
        algorithm_meaning=item.algorithm_meaning,
        role=item.role,
        zone_key=item.zone_key,
        secure_entry_point=item.secure_entry_point,
        key_tag=item.key_tag,
    )
