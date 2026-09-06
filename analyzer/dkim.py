"""DKIM DNS key lookup for a caller-supplied selector (RFC 6376).

DKIM keys live at <selector>._domainkey.<domain>, not at the apex.
This module never guesses selectors (google, s1, default, …). Missing a
selector you named is an observation, not proof that DKIM is absent or
that the domain is compromised.

An empty p= tag means that selector is revoked.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord

_DKIM_PREFIX = re.compile(r"^v=dkim1(?:\s*;|\s*$)", re.IGNORECASE)
_SELECTOR_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$")
_MAX_SELECTOR_CHARS = 200
MAX_SELECTORS = 8

_KEY_TYPES = {
    "rsa": "rsa",
    "ed25519": "ed25519",
}

DKIM_NOTE = (
    "DKIM publishes a public key at a selector name "
    "(selector._domainkey.domain). This tool does not guess selectors. "
    "A missing selector is not proof that mail is unsigned or that the "
    "domain is compromised. Empty p= means that selector is revoked."
)


@dataclass(frozen=True)
class DkimObservation:
    status: str
    selector: str
    query_name: str
    record: str | None
    key_type: str | None
    key_chars: int
    key_present: bool
    revoked: bool
    multiple_records: bool
    note: str = DKIM_NOTE
    error: str | None = None


class DkimSelectorError(ValueError):
    """Raised when a --dkim value cannot be used as a DNS selector."""


def dkim_query_name(domain: str, selector: str) -> str:
    host = domain.rstrip(".").lower()
    label = selector.strip().strip(".").lower()
    return f"{label}._domainkey.{host}"


def normalize_selector(raw: str) -> str:
    """Lowercase DNS labels for a DKIM selector (not a full domain)."""
    if not isinstance(raw, str):
        raise DkimSelectorError("DKIM selector must be a string.")
    value = raw.strip().strip(".").lower()
    if not value:
        raise DkimSelectorError("DKIM selector cannot be empty.")
    if len(value) > _MAX_SELECTOR_CHARS:
        raise DkimSelectorError("DKIM selector is too long.")
    labels = value.split(".")
    if any(not label or not _SELECTOR_LABEL.match(label) for label in labels):
        raise DkimSelectorError(
            f"Invalid DKIM selector {raw!r}. Use DNS labels "
            "(letters, digits, hyphen), for example google or s1."
        )
    return value


def normalize_selectors(raw: Sequence[str]) -> tuple[str, ...]:
    """Deduplicate selectors, keep order, cap how many we query."""
    seen: list[str] = []
    for item in raw:
        selector = normalize_selector(item)
        if selector not in seen:
            seen.append(selector)
    if len(seen) > MAX_SELECTORS:
        raise DkimSelectorError(
            f"Too many --dkim selectors (max {MAX_SELECTORS}). "
            "This tool does not brute-force selector names."
        )
    return tuple(seen)


def evaluate_dkim(
    query_name: str,
    selector: str,
    txt_records: Sequence[DNSRecord],
    error: str | None = None,
) -> DkimObservation:
    """Parse v=DKIM1 TXT at selector._domainkey.<domain>."""
    policies = [
        record.value.strip()
        for record in txt_records
        if _is_dkim(record.value)
    ]
    if not policies:
        return DkimObservation(
            status="NOT DETECTED",
            selector=selector,
            query_name=query_name,
            record=None,
            key_type=None,
            key_chars=0,
            key_present=False,
            revoked=False,
            multiple_records=False,
            error=error,
        )

    tags = _parse_tags(policies[0])
    public = re.sub(r"\s+", "", tags.get("p", ""))
    key_type = _KEY_TYPES.get((tags.get("k") or "rsa").lower(), (tags.get("k") or "rsa").lower())
    revoked = public == ""
    return DkimObservation(
        status="REVOKED" if revoked else "FOUND",
        selector=selector,
        query_name=query_name,
        record=policies[0],
        key_type=key_type,
        key_chars=len(public),
        key_present=bool(public),
        revoked=revoked,
        multiple_records=len(policies) > 1,
        error=error,
    )


def _is_dkim(value: str) -> bool:
    return bool(_DKIM_PREFIX.match(value.strip()))


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
