"""MTA-STS DNS discovery from TXT at _mta-sts.<domain> (RFC 8461).

The TXT record is only an id for a HTTPS policy at
https://mta-sts.<domain>/.well-known/mta-sts.txt. This module does not
fetch that file and is not an SMTP or TLS scanner.

Missing MTA-STS is common. It is an observation, not proof of compromise
or that STARTTLS is unused.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord

_MTASTS_PREFIX = re.compile(r"^v=stsv1\s*;", re.IGNORECASE)

MTASTS_NOTE = (
    "MTA-STS (RFC 8461) publishes a TXT id at _mta-sts.<domain>. "
    "The policy itself is an HTTPS file at mta-sts.<domain>; this tool "
    "does not fetch it. NOT DETECTED does not mean mail is unencrypted "
    "or that the domain is compromised."
)


@dataclass(frozen=True)
class MtaStsObservation:
    status: str
    query_name: str
    policy_host: str
    record: str | None
    policy_id: str | None
    multiple_records: bool
    note: str = MTASTS_NOTE
    error: str | None = None


def mta_sts_query_name(domain: str) -> str:
    return f"_mta-sts.{domain.rstrip('.').lower()}"


def mta_sts_policy_host(domain: str) -> str:
    return f"mta-sts.{domain.rstrip('.').lower()}"


def evaluate_mta_sts(
    query_name: str,
    policy_host: str,
    txt_records: Sequence[DNSRecord],
    error: str | None = None,
) -> MtaStsObservation:
    """Parse v=STSv1 from TXT answers at _mta-sts.<domain>."""
    policies = [
        record.value.strip()
        for record in txt_records
        if _is_mta_sts(record.value)
    ]
    if not policies:
        return MtaStsObservation(
            status="NOT DETECTED",
            query_name=query_name,
            policy_host=policy_host,
            record=None,
            policy_id=None,
            multiple_records=False,
            error=error,
        )
    tags = _parse_tags(policies[0])
    policy_id = tags.get("id") or None
    return MtaStsObservation(
        status="FOUND",
        query_name=query_name,
        policy_host=policy_host,
        record=policies[0],
        policy_id=policy_id,
        multiple_records=len(policies) > 1,
        error=error,
    )


def _is_mta_sts(value: str) -> bool:
    return bool(_MTASTS_PREFIX.match(value.strip()))


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
