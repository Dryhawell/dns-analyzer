"""BIMI DNS discovery from TXT at default._bimi.<domain> (RFC 9091).

BIMI publishes a logo URL (l=) so some inboxes can show a brand mark on
aligned mail. It is not a certificate of authenticity by itself, and this
tool does not fetch the SVG or a VMC (a=).

Only the well-known selector ``default`` is queried. Other selectors are
not guessed. Missing BIMI is common.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord

DEFAULT_SELECTOR = "default"
_BIMI_PREFIX = re.compile(r"^v=bimi1\s*;", re.IGNORECASE)

BIMI_NOTE = (
    "BIMI (RFC 9091) publishes a logo URL at default._bimi.<domain>. "
    "Inboxes typically also require DMARC quarantine or reject. "
    "This tool queries only the default selector and does not fetch "
    "l= or a= URLs. NOT DETECTED is common and is not a compromise."
)


@dataclass(frozen=True)
class BimiObservation:
    status: str
    selector: str
    query_name: str
    record: str | None
    location: str | None
    authority: str | None
    multiple_records: bool
    note: str = BIMI_NOTE
    error: str | None = None


def bimi_query_name(domain: str, selector: str = DEFAULT_SELECTOR) -> str:
    host = domain.rstrip(".").lower()
    return f"{selector}._bimi.{host}"


def evaluate_bimi(
    query_name: str,
    selector: str,
    txt_records: Sequence[DNSRecord],
    error: str | None = None,
) -> BimiObservation:
    """Parse v=BIMI1 from TXT answers at <selector>._bimi.<domain>."""
    policies = [
        record.value.strip()
        for record in txt_records
        if _is_bimi(record.value)
    ]
    if not policies:
        return BimiObservation(
            status="NOT DETECTED",
            selector=selector,
            query_name=query_name,
            record=None,
            location=None,
            authority=None,
            multiple_records=False,
            error=error,
        )
    tags = _parse_tags(policies[0])
    return BimiObservation(
        status="FOUND",
        selector=selector,
        query_name=query_name,
        record=policies[0],
        location=tags.get("l") or None,
        authority=tags.get("a") or None,
        multiple_records=len(policies) > 1,
        error=error,
    )


def _is_bimi(value: str) -> bool:
    return bool(_BIMI_PREFIX.match(value.strip()))


def _parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    body = record.split(";", 1)[1] if ";" in record else ""
    for part in body.split(";"):
        piece = part.strip()
        if not piece or "=" not in piece:
            continue
        key, value = piece.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    return tags
