"""OPENPGPKEY listing for a caller-supplied local-part (RFC 7929).

OPENPGPKEY publishes an OpenPGP transferable public key in DNS. The
owner name is:

    {leftmost 28 octets of SHA-256(prepared local-part), hex}._openpgpkey.<domain>

This tool only lists key length. It does not dump the key, does not
talk to a keyserver, does not send email, and does not invoke GnuPG.

Local-parts are never guessed. Default scans do not query OPENPGPKEY;
pass --openpgpkey LOCALPART.

Hashing uses the shared local-part helper (same 28-octet SHA-256 as
SMIMEA / RFC 8162). RFC 7929 example: hugh@example.com queries
c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._openpgpkey.example.com.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.localpart import (
    HASH_OCTETS,
    MAX_LOCALPARTS,
    LocalpartError,
    hash_localpart,
    normalize_localparts as shared_normalize_localparts,
    prepare_localpart as shared_prepare,
)
from analyzer.models import DNSRecord

MAX_OPENPGPKEY = 8

OPENPGPKEY_NOTE = (
    "OPENPGPKEY (RFC 7929) publishes an OpenPGP public key at "
    "hash._openpgpkey.<domain>. This tool lists key length only. It does "
    "not dump key bytes, does not contact a keyserver, does not send email, "
    "and does not invoke GnuPG. Local-parts are never guessed. A missing "
    "OPENPGPKEY is common and is not a compromise. Listing a record is not "
    "proof that this mailbox uses working OpenPGP, and it is not SMIMEA."
)


@dataclass(frozen=True)
class OpenpgpkeyRecord:
    key_length: int


@dataclass(frozen=True)
class OpenpgpkeyObservation:
    status: str
    local_part: str
    query_name: str
    keys: tuple[OpenpgpkeyRecord, ...]
    truncated: bool = False
    note: str = OPENPGPKEY_NOTE
    error: str | None = None


class OpenpgpkeyLocalpartError(LocalpartError):
    """Raised when a --openpgpkey value cannot be used as a local-part."""


def prepare_localpart(raw: str) -> str:
    """RFC 7929 local-part prepare via the shared helper. No mailbox guessing."""
    try:
        return shared_prepare(raw, label="OPENPGPKEY local-part")
    except LocalpartError as exc:
        raise OpenpgpkeyLocalpartError(str(exc)) from exc


def localpart_hash(local_part: str) -> str:
    """Leftmost 28 octets of SHA-256(prepared local-part), lowercase hex."""
    return hash_localpart(prepare_localpart(local_part))


def openpgpkey_query_name(domain: str, local_part: str) -> str:
    host = domain.rstrip(".").lower()
    return f"{localpart_hash(local_part)}._openpgpkey.{host}"


def normalize_localpart(raw: str) -> str:
    """Prepare one caller-supplied local-part. Never invent a mailbox."""
    return prepare_localpart(raw)


def normalize_localparts(raw: Sequence[str]) -> tuple[str, ...]:
    """Deduplicate local-parts, keep order, cap how many we query."""
    try:
        return shared_normalize_localparts(
            raw, label="OPENPGPKEY local-part", flag="--openpgpkey"
        )
    except LocalpartError as exc:
        raise OpenpgpkeyLocalpartError(str(exc)) from exc


def key_length_of(key: object) -> int:
    """Byte length only. Key material is never returned."""
    if isinstance(key, (bytes, bytearray)):
        return len(key)
    return 0


def record_from_rdata(rdata: object) -> OpenpgpkeyRecord:
    """Build one listing row from dnspython rdata. Key bytes are not kept."""
    return OpenpgpkeyRecord(key_length=key_length_of(getattr(rdata, "key", b"")))


def record_from_record(record: DNSRecord) -> OpenpgpkeyRecord | None:
    """Parse one OPENPGPKEY row. Key bytes are not stored."""
    details = dict(record.details)
    return OpenpgpkeyRecord(
        key_length=_key_length_field(details.get("Key length"), record.value.split())
    )


def evaluate_openpgpkey(
    query_name: str,
    local_part: str,
    records: Sequence[DNSRecord],
    error: str | None = None,
    limit: int = MAX_OPENPGPKEY,
) -> OpenpgpkeyObservation:
    """Map published OPENPGPKEY records to FOUND / NOT DETECTED. No key dump."""
    parsed: list[OpenpgpkeyRecord] = []
    seen: set[int] = set()
    for record in records:
        item = record_from_record(record)
        if item is None:
            continue
        if item.key_length in seen:
            continue
        seen.add(item.key_length)
        parsed.append(item)
    parsed.sort(key=lambda item: item.key_length)
    truncated = len(parsed) > limit
    keys = tuple(parsed[:limit])
    if not keys:
        return OpenpgpkeyObservation(
            status="NOT DETECTED",
            local_part=local_part,
            query_name=query_name,
            keys=(),
            truncated=False,
            error=error,
        )
    return OpenpgpkeyObservation(
        status="FOUND",
        local_part=local_part,
        query_name=query_name,
        keys=keys,
        truncated=truncated,
        error=error,
    )


def format_openpgpkey_value(rdata: object) -> str:
    """Stable listing text. Key bytes are never included."""
    item = record_from_rdata(rdata)
    return f"key-length={item.key_length}"


def openpgpkey_details(rdata: object) -> tuple[tuple[str, str], ...]:
    item = record_from_rdata(rdata)
    return (
        ("Key length", str(item.key_length)),
        (
            "Note",
            "OPENPGPKEY is an OpenPGP public key in DNS, not SMIMEA. Keys are "
            "not dumped; keyservers are not contacted (RFC 7929 listing only).",
        ),
    )


def _key_length_field(labeled: str | None, parts: list[str]) -> int:
    if labeled:
        token = str(labeled).split()[0]
        try:
            return int(token)
        except ValueError:
            pass
    for part in parts:
        if part.startswith("key-length="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return 0
    return 0
