"""DMARC detection from TXT at _dmarc.<domain> (RFC 7489).

DMARC tells receivers what to do when SPF/DKIM alignment fails.
It is a policy signal, not proof of compromise.

DKIM is not auto-discovered here: a selector (e.g. google._domainkey.example.com)
must be known first.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord

_DMARC_PREFIX = re.compile(r"^v=dmarc1\s*;", re.IGNORECASE)

_POLICY_MEANING = {
    "none": "monitor only — delivery is not changed",
    "quarantine": "typically place failing mail in spam/junk",
    "reject": "reject failing mail at the receiving server",
}

DMARC_NOTE = (
    "DMARC is a receiver policy for unaligned mail (SPF/DKIM). "
    "NOT DETECTED does not mean the domain is compromised. "
    "p=none is visibility, not enforcement. "
    "DKIM requires a selector and is not guessed in this phase."
)


@dataclass(frozen=True)
class DmarcObservation:
    status: str
    query_name: str
    record: str | None
    policy: str | None
    policy_meaning: str | None
    subdomain_policy: str | None
    pct: str | None
    rua: str | None
    multiple_records: bool
    note: str = DMARC_NOTE
    error: str | None = None


def dmarc_query_name(domain: str) -> str:
    return f"_dmarc.{domain.rstrip('.').lower()}"


def evaluate_dmarc(
    query_name: str,
    txt_records: Sequence[DNSRecord],
    error: str | None = None,
) -> DmarcObservation:
    """Parse v=DMARC1 from TXT answers at _dmarc.<domain>."""
    policies = [
        record.value.strip()
        for record in txt_records
        if _is_dmarc(record.value)
    ]

    if not policies:
        return DmarcObservation(
            status="NOT DETECTED",
            query_name=query_name,
            record=None,
            policy=None,
            policy_meaning=None,
            subdomain_policy=None,
            pct=None,
            rua=None,
            multiple_records=False,
            error=error,
        )

    tags = _parse_tags(policies[0])
    policy = (tags.get("p") or "").lower() or None
    sp = (tags.get("sp") or "").lower() or None
    return DmarcObservation(
        status="FOUND",
        query_name=query_name,
        record=policies[0],
        policy=policy,
        policy_meaning=_POLICY_MEANING.get(policy or ""),
        subdomain_policy=sp,
        pct=tags.get("pct"),
        rua=tags.get("rua"),
        multiple_records=len(policies) > 1,
        error=error,
    )


def _is_dmarc(value: str) -> bool:
    return bool(_DMARC_PREFIX.match(value.strip()))


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
