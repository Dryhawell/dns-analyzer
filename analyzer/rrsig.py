"""RRSIG listing (RFC 4034). Signatures at this name, not validation.

RRSIG covers a record type with a DNSKEY (algorithm + key tag). This tool
lists type covered, algorithm, labels, original TTL, inception, expiration,
key tag, signer, and signature length.

It does not validate signatures, does not check the key tag against DNSKEY,
does not walk the chain of trust, does not fetch HTTP, and does not AXFR.

NOT DETECTED is common. Unsigned zones have no RRSIG. Absence is not broken
DNSSEC and is not a compromise. Listing a signature is not a validity verdict.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

from analyzer.dnssec import algorithm_meaning

MAX_RRSIG_ITEMS = 8

RRSIG_NOTE = (
    "RRSIG (RFC 4034) is a signature over a DNS RRset at this name. "
    "This tool lists type covered, algorithm, labels, original TTL, "
    "inception, expiration, key tag, signer, and signature length. "
    "It does not validate the signature, does not check the key tag against "
    "DNSKEY, and does not walk the chain of trust. Signature bytes are not "
    "dumped. Dates are listed as published; this is not a valid/invalid "
    "verdict. NOT DETECTED is common on unsigned zones. Absence is not "
    "broken DNSSEC and is not a compromise."
)


@dataclass(frozen=True)
class RrsigRecord:
    type_covered: int
    type_covered_name: str
    algorithm: int
    algorithm_meaning: str
    labels: int
    original_ttl: int
    inception: int
    expiration: int
    inception_utc: str
    expiration_utc: str
    key_tag: int
    signer: str
    signature_length: int


@dataclass(frozen=True)
class RrsigObservation:
    status: str
    query_name: str
    rrsig: tuple[RrsigRecord, ...] = ()
    truncated: bool = False
    note: str = RRSIG_NOTE
    error: str | None = None


def evaluate_rrsig(
    query_name: str,
    *,
    found: bool,
    rrsig: Sequence[RrsigRecord] = (),
    truncated: bool = False,
    error: str | None = None,
) -> RrsigObservation:
    """Map published RRSIG to FOUND / NOT DETECTED. Timeout stays unread, not missing."""
    if found:
        status = "FOUND"
    elif error:
        status = "UNREADABLE"
    else:
        status = "NOT DETECTED"
    return RrsigObservation(
        status=status,
        query_name=query_name,
        rrsig=tuple(rrsig),
        truncated=truncated,
        error=error,
    )


def parse_rrsig(
    rdatas: Sequence[object],
    limit: int = MAX_RRSIG_ITEMS,
) -> tuple[tuple[RrsigRecord, ...], bool]:
    parsed: list[RrsigRecord] = []
    seen: set[tuple[int, int, int, int, int]] = set()
    for rdata in rdatas:
        item = _from_rdata(rdata)
        key = (
            item.type_covered,
            item.algorithm,
            item.key_tag,
            item.inception,
            item.expiration,
        )
        if key in seen:
            continue
        seen.add(key)
        parsed.append(item)
    truncated = len(parsed) > limit
    return tuple(parsed[:limit]), truncated


def format_rrsig_value(rdata: object) -> str:
    """Human value without signature bytes."""
    item = _from_rdata(rdata)
    return (
        f"{item.type_covered_name} alg {item.algorithm} labels {item.labels} "
        f"origttl {item.original_ttl} {item.inception_utc} {item.expiration_utc} "
        f"key {item.key_tag} {item.signer} (sig length {item.signature_length})"
    )


def rrsig_details(rdata: object) -> tuple[tuple[str, str], ...]:
    item = _from_rdata(rdata)
    return (
        ("Type covered", f"{item.type_covered} {item.type_covered_name}"),
        ("Algorithm", f"{item.algorithm} — {item.algorithm_meaning}"),
        ("Labels", str(item.labels)),
        ("Original TTL", str(item.original_ttl)),
        ("Inception", item.inception_utc),
        ("Expiration", item.expiration_utc),
        ("Key tag", str(item.key_tag)),
        ("Signer", item.signer),
        ("Signature length", str(item.signature_length)),
        (
            "Note",
            "RRSIG is listed, not validated. Signature bytes are not dumped.",
        ),
    )


def _from_rdata(rdata: object) -> RrsigRecord:
    type_covered, type_name = _type_covered(rdata)
    algorithm = int(getattr(rdata, "algorithm", 0) or 0)
    inception, inception_utc = _unix_and_utc(getattr(rdata, "inception", 0))
    expiration, expiration_utc = _unix_and_utc(getattr(rdata, "expiration", 0))
    return RrsigRecord(
        type_covered=type_covered,
        type_covered_name=type_name,
        algorithm=algorithm,
        algorithm_meaning=algorithm_meaning(algorithm),
        labels=int(getattr(rdata, "labels", 0) or 0),
        original_ttl=int(getattr(rdata, "original_ttl", 0) or 0),
        inception=inception,
        expiration=expiration,
        inception_utc=inception_utc,
        expiration_utc=expiration_utc,
        key_tag=int(getattr(rdata, "key_tag", 0) or 0),
        signer=_signer(rdata),
        signature_length=_signature_length(rdata),
    )


def _type_covered(rdata: object) -> tuple[int, str]:
    raw = getattr(rdata, "type_covered", None)
    if raw is None:
        covers = getattr(rdata, "covers", None)
        raw = covers() if callable(covers) else covers
    if raw is None:
        return 0, "TYPE0"
    number = int(raw)
    name = _type_name(number, raw)
    return number, name


def _type_name(number: int, raw: object) -> str:
    text = getattr(raw, "name", None)
    if isinstance(text, str) and text.isalpha():
        return text.upper()
    try:
        import dns.rdatatype

        return dns.rdatatype.to_text(number)
    except Exception:
        return f"TYPE{number}"


def _unix_and_utc(value: object) -> tuple[int, str]:
    if isinstance(value, datetime):
        aware = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        aware = aware.astimezone(timezone.utc)
        return int(aware.timestamp()), aware.strftime("%Y-%m-%dT%H:%M:%SZ")
    text = str(value).strip() if value is not None else "0"
    if len(text) == 14 and text.isdigit():
        parsed = datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        return int(parsed.timestamp()), parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        timestamp = int(value or 0)
    except (TypeError, ValueError):
        timestamp = 0
    if timestamp < 0:
        timestamp = 0
    stamped = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return timestamp, stamped.strftime("%Y-%m-%dT%H:%M:%SZ")


def _signer(rdata: object) -> str:
    signer = getattr(rdata, "signer", None)
    if signer is None:
        return ""
    return str(signer).rstrip(".").lower()


def _signature_length(rdata: object) -> int:
    signature = getattr(rdata, "signature", b"")
    if signature in (None, b"", ""):
        return 0
    if isinstance(signature, (bytes, bytearray)):
        return len(signature)
    text = str(signature).strip()
    if text.startswith("\\#"):
        return 0
    hex_text = text.replace(" ", "")
    if hex_text and all(ch in "0123456789abcdefABCDEF" for ch in hex_text):
        return (len(hex_text) + 1) // 2
    return len(text)
