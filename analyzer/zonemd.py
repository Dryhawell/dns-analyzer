"""ZONEMD listing (RFC 8976). Zone digest at the apex, not AXFR.

ZONEMD publishes a digest of the zone so a copy can be checked without
trusting only the transfer path. This tool only lists scheme, hash
algorithm, SOA serial, and digest length.

It does not fetch the zone (no AXFR/IXFR), does not recompute the digest,
and does not compare ZONEMD serial to SOA serial.

NOT DETECTED is common. Many signed zones never publish ZONEMD. Absence
is not broken DNSSEC and is not a compromise.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

MAX_ZONEMD_ITEMS = 8

_SCHEME_MEANING = {
    1: "SIMPLE",
}

_HASH_MEANING = {
    1: "SHA-384",
    2: "SHA-512",
}

ZONEMD_NOTE = (
    "ZONEMD (RFC 8976) publishes a digest of the zone at the apex. "
    "This tool lists scheme, hash algorithm, SOA serial, and digest length. "
    "It does not fetch the zone (no AXFR/IXFR), does not recompute the digest, "
    "and does not compare ZONEMD serial to SOA serial. "
    "Digest bytes are not dumped. NOT DETECTED is common; many zones never "
    "publish ZONEMD. Absence is not broken DNSSEC and is not a compromise. "
    "The serial is a change counter, not a security score."
)


@dataclass(frozen=True)
class ZonemdRecord:
    serial: int
    scheme: int
    scheme_meaning: str
    hash_algorithm: int
    hash_meaning: str
    digest_length: int


@dataclass(frozen=True)
class ZonemdObservation:
    status: str
    query_name: str
    zonemd: tuple[ZonemdRecord, ...] = ()
    truncated: bool = False
    note: str = ZONEMD_NOTE
    error: str | None = None


def evaluate_zonemd(
    query_name: str,
    *,
    found: bool,
    zonemd: Sequence[ZonemdRecord] = (),
    truncated: bool = False,
    error: str | None = None,
) -> ZonemdObservation:
    """Map published ZONEMD to FOUND / NOT DETECTED / UNREADABLE."""
    if found:
        status = "FOUND"
    elif error:
        status = "UNREADABLE"
    else:
        status = "NOT DETECTED"
    return ZonemdObservation(
        status=status,
        query_name=query_name,
        zonemd=tuple(zonemd),
        truncated=truncated,
        error=error,
    )


def parse_zonemd(
    rdatas: Sequence[object],
    limit: int = MAX_ZONEMD_ITEMS,
) -> tuple[tuple[ZonemdRecord, ...], bool]:
    parsed: list[ZonemdRecord] = []
    for rdata in rdatas:
        scheme = int(getattr(rdata, "scheme", 0) or 0)
        algorithm = int(
            getattr(rdata, "hash_algorithm", None)
            or getattr(rdata, "hashalg", 0)
            or 0
        )
        parsed.append(
            ZonemdRecord(
                serial=int(getattr(rdata, "serial", 0) or 0),
                scheme=scheme,
                scheme_meaning=_SCHEME_MEANING.get(scheme, f"scheme {scheme}"),
                hash_algorithm=algorithm,
                hash_meaning=_HASH_MEANING.get(
                    algorithm, f"hash algorithm {algorithm}"
                ),
                digest_length=_digest_length(rdata),
            )
        )
    truncated = len(parsed) > limit
    return tuple(parsed[:limit]), truncated


def _digest_length(rdata: object) -> int:
    digest = getattr(rdata, "digest", b"")
    if digest in (None, b"", ""):
        return 0
    if isinstance(digest, (bytes, bytearray)):
        return len(digest)
    text = str(digest).strip()
    if text.startswith("\\#"):
        return 0
    hex_text = text.replace(" ", "")
    if hex_text and all(ch in "0123456789abcdefABCDEF" for ch in hex_text):
        return (len(hex_text) + 1) // 2
    return len(text)
