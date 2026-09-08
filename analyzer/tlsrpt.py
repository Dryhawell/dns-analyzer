"""TLS-RPT DNS discovery from TXT at _smtp._tls.<domain> (RFC 8460).

TLS-RPT tells senders where to mail JSON reports about SMTP TLS failures
(STARTTLS downgrade, certificate mismatch). It is a reporting address,
not proof that TLS is enforced.

This module does not send SMTP, does not fetch HTTPS rua endpoints, and
does not validate certificates. Missing TLS-RPT is common.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord

_TLSRPT_PREFIX = re.compile(r"^v=tlsrptv1\s*;", re.IGNORECASE)

TLSRPT_NOTE = (
    "TLS-RPT (RFC 8460) publishes a report destination at "
    "_smtp._tls.<domain>. It does not encrypt mail. NOT DETECTED does "
    "not mean STARTTLS is unused or that the domain is compromised. "
    "This tool does not send SMTP or fetch HTTPS rua URLs."
)


@dataclass(frozen=True)
class TlsRptObservation:
    status: str
    query_name: str
    record: str | None
    rua: str | None
    multiple_records: bool
    note: str = TLSRPT_NOTE
    error: str | None = None


def tls_rpt_query_name(domain: str) -> str:
    return f"_smtp._tls.{domain.rstrip('.').lower()}"


def evaluate_tls_rpt(
    query_name: str,
    txt_records: Sequence[DNSRecord],
    error: str | None = None,
) -> TlsRptObservation:
    """Parse v=TLSRPTv1 from TXT answers at _smtp._tls.<domain>."""
    policies = [
        record.value.strip()
        for record in txt_records
        if _is_tls_rpt(record.value)
    ]
    if not policies:
        return TlsRptObservation(
            status="NOT DETECTED",
            query_name=query_name,
            record=None,
            rua=None,
            multiple_records=False,
            error=error,
        )
    tags = _parse_tags(policies[0])
    rua = tags.get("rua") or None
    return TlsRptObservation(
        status="FOUND",
        query_name=query_name,
        record=policies[0],
        rua=rua,
        multiple_records=len(policies) > 1,
        error=error,
    )


def _is_tls_rpt(value: str) -> bool:
    return bool(_TLSRPT_PREFIX.match(value.strip()))


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
