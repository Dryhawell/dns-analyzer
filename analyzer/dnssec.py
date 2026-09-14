"""DNSSEC detection — observation only, not a verdict.

DNSSEC adds signatures (RRSIG) and keys (DNSKEY). The parent zone stores a
DS hash so a validating resolver can build a chain to the IANA root.

This module checks whether DNSKEY/DS are published and whether THIS
resolver set the AD (Authenticated Data) flag. It does not validate the
full chain against the root key.

NOT DETECTED does not mean the domain is compromised. Listing an algorithm
is not a cryptographic validation and is not a compromise grade.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

MAX_DNSSEC_ITEMS = 8

# Zone Key (ZSK) and Secure Entry Point (SEP / typically KSK) flag bits.
ZONE_KEY_FLAG = 256
SEP_FLAG = 1

# SHA-1-era algorithms (IANA DNSKEY). Deprecated, not a breach.
SHA1_ERA_ALGORITHMS = frozenset({1, 3, 5, 6, 7})
SHA1_DS_DIGEST = 1

_ALGORITHM_MEANING = {
    1: "RSA/MD5 (deprecated)",
    3: "DSA/SHA-1",
    5: "RSA/SHA-1",
    6: "DSA-NSEC3-SHA1",
    7: "RSASHA1-NSEC3-SHA1",
    8: "RSA/SHA-256",
    10: "RSA/SHA-512",
    12: "GOST R 34.10-2001",
    13: "ECDSAP256SHA256",
    14: "ECDSAP384SHA384",
    15: "Ed25519",
    16: "Ed448",
}

_DIGEST_MEANING = {
    1: "SHA-1",
    2: "SHA-256",
    4: "SHA-384",
}

DNSSEC_NOTE = (
    "DNSSEC authenticates DNS responses (integrity). "
    "NOT DETECTED does not mean the domain is compromised. "
    "This is not a full chain-of-trust validation against the IANA root key. "
    "Some recursive resolvers strip DNSKEY/DS or never set the AD flag, "
    "so a signed zone can still look undetected here. "
    "Listed algorithms are labels from this resolver's answer, not a proof "
    "that the chain is valid."
)


@dataclass(frozen=True)
class DnssecKey:
    flags: int
    protocol: int
    algorithm: int
    algorithm_meaning: str
    role: str
    zone_key: bool
    secure_entry_point: bool
    key_tag: int | None


@dataclass(frozen=True)
class DnssecDelegation:
    key_tag: int
    algorithm: int
    algorithm_meaning: str
    digest_type: int
    digest_meaning: str


@dataclass(frozen=True)
class DnssecObservation:
    status: str
    dnskey_found: bool
    ds_found: bool
    ad_flag: bool
    note: str = DNSSEC_NOTE
    error: str | None = None
    keys: tuple[DnssecKey, ...] = ()
    delegations: tuple[DnssecDelegation, ...] = ()
    keys_truncated: bool = False
    delegations_truncated: bool = False


def evaluate_dnssec(
    *,
    dnskey_found: bool,
    ds_found: bool,
    ad_flag: bool,
    error: str | None = None,
    keys: Sequence[DnssecKey] = (),
    delegations: Sequence[DnssecDelegation] = (),
    keys_truncated: bool = False,
    delegations_truncated: bool = False,
) -> DnssecObservation:
    """Map published records to DETECTED / NOT DETECTED.

    ENABLED in the product spec means 'signals present', not 'cryptographically
    proven by this tool'. We use DETECTED for that reason.
    """
    detected = dnskey_found or ds_found
    return DnssecObservation(
        status="DETECTED" if detected else "NOT DETECTED",
        dnskey_found=dnskey_found,
        ds_found=ds_found,
        ad_flag=ad_flag,
        error=error,
        keys=tuple(keys),
        delegations=tuple(delegations),
        keys_truncated=keys_truncated,
        delegations_truncated=delegations_truncated,
    )


def algorithm_meaning(algorithm: int) -> str:
    return _ALGORITHM_MEANING.get(algorithm, "unknown algorithm")


def digest_meaning(digest_type: int) -> str:
    return _DIGEST_MEANING.get(digest_type, "unknown digest")


def key_role(flags: int) -> str:
    if flags & SEP_FLAG:
        return "KSK"
    if flags & ZONE_KEY_FLAG:
        return "ZSK"
    return "other"


def key_from_rdata(rdata: object) -> DnssecKey | None:
    """Build a DnssecKey from DNSKEY rdata. Public key material is omitted."""
    flags = getattr(rdata, "flags", None)
    protocol = getattr(rdata, "protocol", None)
    algorithm = getattr(rdata, "algorithm", None)
    if not isinstance(flags, int) or not isinstance(protocol, int):
        return None
    if not isinstance(algorithm, int):
        return None
    return DnssecKey(
        flags=flags,
        protocol=protocol,
        algorithm=algorithm,
        algorithm_meaning=algorithm_meaning(algorithm),
        role=key_role(flags),
        zone_key=bool(flags & ZONE_KEY_FLAG),
        secure_entry_point=bool(flags & SEP_FLAG),
        key_tag=_key_tag(rdata),
    )


def delegation_from_rdata(rdata: object) -> DnssecDelegation | None:
    """Build a DS view. Digest bytes are omitted (type only)."""
    key_tag = getattr(rdata, "key_tag", None)
    algorithm = getattr(rdata, "algorithm", None)
    digest_type = getattr(rdata, "digest_type", None)
    if not isinstance(key_tag, int) or not isinstance(algorithm, int):
        return None
    if not isinstance(digest_type, int):
        return None
    return DnssecDelegation(
        key_tag=key_tag,
        algorithm=algorithm,
        algorithm_meaning=algorithm_meaning(algorithm),
        digest_type=digest_type,
        digest_meaning=digest_meaning(digest_type),
    )


def parse_dnskeys(
    rdatas: Sequence[object],
    limit: int = MAX_DNSSEC_ITEMS,
) -> tuple[tuple[DnssecKey, ...], bool]:
    parsed: list[DnssecKey] = []
    truncated = False
    for rdata in rdatas:
        key = key_from_rdata(rdata)
        if key is None:
            continue
        if len(parsed) >= limit:
            truncated = True
            break
        parsed.append(key)
    return tuple(parsed), truncated


def parse_delegations(
    rdatas: Sequence[object],
    limit: int = MAX_DNSSEC_ITEMS,
) -> tuple[tuple[DnssecDelegation, ...], bool]:
    parsed: list[DnssecDelegation] = []
    truncated = False
    for rdata in rdatas:
        item = delegation_from_rdata(rdata)
        if item is None:
            continue
        if len(parsed) >= limit:
            truncated = True
            break
        parsed.append(item)
    return tuple(parsed), truncated


def _key_tag(rdata: object) -> int | None:
    try:
        import dns.dnssec

        return int(dns.dnssec.key_id(rdata))
    except (TypeError, ValueError, AttributeError, OSError):
        return None
