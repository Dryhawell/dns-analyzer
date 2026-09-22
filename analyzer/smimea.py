"""SMIMEA listing for a caller-supplied local-part (RFC 8162).

SMIMEA publishes a DANE certificate association for S/MIME, not for
HTTPS. The owner name is:

    {leftmost 28 octets of SHA-256(prepared local-part), hex}._smimecert.<domain>

This tool only lists usage, selector, matching type, and association
length. It does not send email, does not fetch certificates, and does
not probe SMTP, IMAP, or TLS.

Local-parts are never guessed. Default scans do not query SMIMEA;
pass --smimea LOCALPART.

Canonicalization (RFC 8162 section 3, documented):
- If the user passes an email address, only the local-part (before @) is used
- Unquoted CFWS around dots is removed; enclosing quotes and literal
  quoting are stripped
- Non-ASCII is NFC-normalized (RFC 8162); ASCII letters are lowercased
  (common operator practice for case-insensitive mailboxes, RFC 8162 §4)
- The prepared string is UTF-8 encoded, then SHA-256; the leftmost 28
  octets become the leftmost DNS label
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord
from analyzer.tlsa import matching_meaning, selector_meaning, usage_meaning

MAX_SMIMEA = 8
MAX_LOCALPARTS = 8
HASH_OCTETS = 28
_MAX_LOCALPART_OCTETS = 64

_COMMENT = re.compile(r"\([^)]*\)")

SMIMEA_NOTE = (
    "SMIMEA (RFC 8162) publishes a DANE certificate association for S/MIME "
    "at hash._smimecert.<domain>. This is not TLSA for HTTPS. This tool lists "
    "usage, selector, matching type, and association length. It does not send "
    "email, does not fetch certificates, and does not probe SMTP, IMAP, or TLS. "
    "Local-parts are never guessed. A missing SMIMEA is common and is not a "
    "compromise. Listing a record is not certificate validation."
)


@dataclass(frozen=True)
class SmimeaAssociation:
    usage: int
    selector: int
    matching_type: int
    association_length: int
    usage_meaning: str
    selector_meaning: str
    matching_meaning: str


@dataclass(frozen=True)
class SmimeaObservation:
    status: str
    local_part: str
    query_name: str
    associations: tuple[SmimeaAssociation, ...]
    truncated: bool = False
    note: str = SMIMEA_NOTE
    error: str | None = None


class SmimeaLocalpartError(ValueError):
    """Raised when a --smimea value cannot be used as a local-part."""


def prepare_localpart(raw: str) -> str:
    """RFC 8162 §3 prepare, plus documented ASCII lowercase. No mailbox guessing."""
    if not isinstance(raw, str):
        raise SmimeaLocalpartError("SMIMEA local-part must be a string.")
    value = raw.strip()
    if "@" in value:
        value = value.split("@", 1)[0].strip()
    if not value:
        raise SmimeaLocalpartError(
            "SMIMEA local-part cannot be empty. Pass the part before @, "
            "for example alice, not a guessed mailbox list."
        )
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    value = _COMMENT.sub("", value)
    value = re.sub(r"\s*\.\s*", ".", value)
    value = value.replace("\\", "")
    value = value.strip()
    if any(ord(char) > 127 for char in value):
        value = unicodedata.normalize("NFC", value)
    value = "".join(char.lower() if char.isascii() else char for char in value)
    if not value:
        raise SmimeaLocalpartError(
            "SMIMEA local-part cannot be empty after RFC 8162 preparation."
        )
    encoded = value.encode("utf-8")
    if len(encoded) > _MAX_LOCALPART_OCTETS:
        raise SmimeaLocalpartError("SMIMEA local-part is too long.")
    if any(ord(char) < 32 for char in value):
        raise SmimeaLocalpartError(
            f"Invalid SMIMEA local-part {raw!r}. Pass a mailbox local-part "
            "(the part before @). Local-parts are never guessed."
        )
    return value


def localpart_hash(local_part: str) -> str:
    """Leftmost 28 octets of SHA-256(prepared local-part), lowercase hex."""
    prepared = prepare_localpart(local_part)
    digest = hashlib.sha256(prepared.encode("utf-8")).digest()
    return digest[:HASH_OCTETS].hex()


def smimea_query_name(domain: str, local_part: str) -> str:
    host = domain.rstrip(".").lower()
    return f"{localpart_hash(local_part)}._smimecert.{host}"


def normalize_localpart(raw: str) -> str:
    """Prepare one caller-supplied local-part. Never invent a mailbox."""
    return prepare_localpart(raw)


def normalize_localparts(raw: Sequence[str]) -> tuple[str, ...]:
    """Deduplicate local-parts, keep order, cap how many we query."""
    seen: list[str] = []
    for item in raw:
        local_part = normalize_localpart(item)
        if local_part not in seen:
            seen.append(local_part)
    if len(seen) > MAX_LOCALPARTS:
        raise SmimeaLocalpartError(
            f"Too many --smimea local-parts (max {MAX_LOCALPARTS}). "
            "This tool does not brute-force or guess mailbox names."
        )
    return tuple(seen)


def association_length_of(cert: object) -> int:
    """Byte length only. Certificate / key material is never returned."""
    if isinstance(cert, (bytes, bytearray)):
        return len(cert)
    return 0


def record_from_rdata(rdata: object) -> SmimeaAssociation:
    """Build one listing row from dnspython rdata. Association bytes are not kept."""
    usage = int(getattr(rdata, "usage", 0))
    selector = int(getattr(rdata, "selector", 0))
    matching_type = int(getattr(rdata, "mtype", 0))
    return SmimeaAssociation(
        usage=usage,
        selector=selector,
        matching_type=matching_type,
        association_length=association_length_of(getattr(rdata, "cert", b"")),
        usage_meaning=usage_meaning(usage),
        selector_meaning=selector_meaning(selector),
        matching_meaning=matching_meaning(matching_type),
    )


def record_from_record(record: DNSRecord) -> SmimeaAssociation | None:
    """Parse one SMIMEA row. Association bytes are not stored."""
    details = dict(record.details)
    parts = record.value.split()
    usage = _int_field(details.get("Usage"), parts, 0)
    selector = _int_field(details.get("Selector"), parts, 1)
    matching_type = _int_field(details.get("Matching"), parts, 2)
    if usage < 0 or selector < 0 or matching_type < 0:
        return None
    return SmimeaAssociation(
        usage=usage,
        selector=selector,
        matching_type=matching_type,
        association_length=_assoc_length_field(details.get("Association length"), parts),
        usage_meaning=usage_meaning(usage),
        selector_meaning=selector_meaning(selector),
        matching_meaning=matching_meaning(matching_type),
    )


def evaluate_smimea(
    query_name: str,
    local_part: str,
    records: Sequence[DNSRecord],
    error: str | None = None,
    limit: int = MAX_SMIMEA,
) -> SmimeaObservation:
    """Map published SMIMEA records to FOUND / NOT DETECTED. No cert fetch."""
    parsed: list[SmimeaAssociation] = []
    seen: set[tuple[int, int, int, int]] = set()
    for record in records:
        item = record_from_record(record)
        if item is None:
            continue
        key = (item.usage, item.selector, item.matching_type, item.association_length)
        if key in seen:
            continue
        seen.add(key)
        parsed.append(item)
    parsed.sort(
        key=lambda item: (
            item.usage,
            item.selector,
            item.matching_type,
            item.association_length,
        )
    )
    truncated = len(parsed) > limit
    associations = tuple(parsed[:limit])
    if not associations:
        return SmimeaObservation(
            status="NOT DETECTED",
            local_part=local_part,
            query_name=query_name,
            associations=(),
            truncated=False,
            error=error,
        )
    return SmimeaObservation(
        status="FOUND",
        local_part=local_part,
        query_name=query_name,
        associations=associations,
        truncated=truncated,
        error=error,
    )


def format_smimea_value(rdata: object) -> str:
    """Stable listing text. Association bytes are never included."""
    item = record_from_rdata(rdata)
    return (
        f"{item.usage} {item.selector} {item.matching_type} "
        f"assoc-length={item.association_length}"
    )


def smimea_details(rdata: object) -> tuple[tuple[str, str], ...]:
    item = record_from_rdata(rdata)
    return (
        ("Usage", f"{item.usage} — {item.usage_meaning}"),
        ("Selector", f"{item.selector} — {item.selector_meaning}"),
        ("Matching", f"{item.matching_type} — {item.matching_meaning}"),
        ("Association length", str(item.association_length)),
        (
            "Note",
            "SMIMEA is DANE for S/MIME, not TLSA for HTTPS. Certificates are "
            "not fetched; association bytes are not dumped (RFC 8162 listing only).",
        ),
    )


def _int_field(labeled: str | None, parts: list[str], index: int) -> int:
    if labeled:
        token = labeled.split("—", 1)[0].split("-", 1)[0].strip()
        try:
            return int(token)
        except ValueError:
            pass
    if index < len(parts):
        try:
            return int(parts[index])
        except ValueError:
            return -1
    return -1


def _assoc_length_field(labeled: str | None, parts: list[str]) -> int:
    if labeled:
        token = str(labeled).split()[0]
        try:
            return int(token)
        except ValueError:
            pass
    for part in parts:
        if part.startswith("assoc-length="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return 0
    return 0
