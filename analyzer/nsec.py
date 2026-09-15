"""NSEC / NSEC3PARAM listing (RFC 4034 / 5155). Authenticated denial, not walking.

NSEC proves that a name or type is absent, but the next owner name is
visible. Walking that chain enumerates the zone; this tool does not.

NSEC3PARAM at the apex describes how NSEC3 hashes owner names. This tool
does not synthesize hashed names and does not query NSEC3.

NOT DETECTED is common. Unsigned zones have neither record. Absence is
not broken DNSSEC and is not a compromise.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

MAX_NSEC_ITEMS = 8
MAX_NSEC_TYPES = 16

_HASH_MEANING = {
    1: "SHA-1 (NSEC3 hash)",
}

NSEC_NOTE = (
    "NSEC (RFC 4034) and NSEC3PARAM (RFC 5155) describe authenticated denial "
    "of existence at this name. This tool lists records visible to this "
    "resolver. It does not walk the NSEC/NSEC3 chain, does not synthesize "
    "hashed owner names, and does not query NSEC3. Listing a next name is "
    "not zone enumeration. NOT DETECTED is common on unsigned zones. "
    "Absence is not broken DNSSEC and is not a compromise."
)


@dataclass(frozen=True)
class NsecRecord:
    next_name: str
    types: tuple[str, ...]
    types_truncated: bool = False


@dataclass(frozen=True)
class Nsec3ParamRecord:
    algorithm: int
    algorithm_meaning: str
    flags: int
    opt_out: bool
    iterations: int
    salt_length: int
    iterations_note: str


@dataclass(frozen=True)
class NsecObservation:
    status: str
    query_name: str
    nsec_found: bool
    nsec3param_found: bool
    nsec: tuple[NsecRecord, ...] = ()
    nsec3param: tuple[Nsec3ParamRecord, ...] = ()
    nsec_truncated: bool = False
    nsec3param_truncated: bool = False
    note: str = NSEC_NOTE
    error: str | None = None


def evaluate_nsec(
    query_name: str,
    *,
    nsec_found: bool,
    nsec3param_found: bool,
    nsec: Sequence[NsecRecord] = (),
    nsec3param: Sequence[Nsec3ParamRecord] = (),
    nsec_truncated: bool = False,
    nsec3param_truncated: bool = False,
    error: str | None = None,
) -> NsecObservation:
    """Map published NSEC/NSEC3PARAM to FOUND / NOT DETECTED / UNREADABLE."""
    found = nsec_found or nsec3param_found
    if found:
        status = "FOUND"
    elif error:
        status = "UNREADABLE"
    else:
        status = "NOT DETECTED"
    return NsecObservation(
        status=status,
        query_name=query_name,
        nsec_found=nsec_found,
        nsec3param_found=nsec3param_found,
        nsec=tuple(nsec),
        nsec3param=tuple(nsec3param),
        nsec_truncated=nsec_truncated,
        nsec3param_truncated=nsec3param_truncated,
        error=error,
    )


def parse_nsec(
    rdatas: Sequence[object],
    limit: int = MAX_NSEC_ITEMS,
) -> tuple[tuple[NsecRecord, ...], bool]:
    parsed: list[NsecRecord] = []
    for rdata in rdatas:
        types, types_truncated = _nsec_types(rdata)
        parsed.append(
            NsecRecord(
                next_name=_next_name(rdata),
                types=types,
                types_truncated=types_truncated,
            )
        )
    truncated = len(parsed) > limit
    return tuple(parsed[:limit]), truncated


def parse_nsec3param(
    rdatas: Sequence[object],
    limit: int = MAX_NSEC_ITEMS,
) -> tuple[tuple[Nsec3ParamRecord, ...], bool]:
    parsed: list[Nsec3ParamRecord] = []
    for rdata in rdatas:
        algorithm = int(getattr(rdata, "algorithm", 0) or 0)
        flags = int(getattr(rdata, "flags", 0) or 0)
        iterations = int(getattr(rdata, "iterations", 0) or 0)
        parsed.append(
            Nsec3ParamRecord(
                algorithm=algorithm,
                algorithm_meaning=_HASH_MEANING.get(
                    algorithm, f"hash algorithm {algorithm}"
                ),
                flags=flags,
                opt_out=bool(flags & 0x01),
                iterations=iterations,
                salt_length=_salt_length(rdata),
                iterations_note=_iterations_note(iterations),
            )
        )
    truncated = len(parsed) > limit
    return tuple(parsed[:limit]), truncated


def _next_name(rdata: object) -> str:
    nxt = getattr(rdata, "next", None)
    if nxt is None:
        text = str(rdata).split(None, 1)
        return text[0].rstrip(".").lower() if text else ""
    return str(nxt).rstrip(".").lower()


def _nsec_types(rdata: object) -> tuple[tuple[str, ...], bool]:
    explicit = getattr(rdata, "types", None)
    if explicit is not None:
        names = tuple(str(item) for item in explicit)
        truncated = len(names) > MAX_NSEC_TYPES
        return names[:MAX_NSEC_TYPES], truncated
    to_text = getattr(rdata, "to_text", None)
    if callable(to_text):
        tokens = to_text().split()
        names = tuple(token.rstrip(".") for token in tokens[1:] if token)
        truncated = len(names) > MAX_NSEC_TYPES
        return names[:MAX_NSEC_TYPES], truncated
    return (), False


def _salt_length(rdata: object) -> int:
    salt = getattr(rdata, "salt", b"")
    if salt in (None, b"", "", "-"):
        return 0
    if isinstance(salt, (bytes, bytearray)):
        return len(salt)
    text = str(salt).strip()
    if text in {"", "-"}:
        return 0
    return len(text)


def _iterations_note(iterations: int) -> str:
    if iterations == 0:
        return "0 iterations (RFC 9276)"
    return "RFC 9276 recommends 0 NSEC3 iterations; this is not a compromise"
