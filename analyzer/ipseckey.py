"""IPSECKEY listing for a caller-supplied name (RFC 4025).

IPSECKEY publishes an IPsec gateway and a public key in DNS. This tool
only lists precedence, gateway type, algorithm, gateway, and key length.
It does not probe IPsec or IKE, does not dump key material, and does not
resolve a gateway domain name.

Missing IPSECKEY is common and is not a compromise. Default scans do not
query IPSECKEY; pass --ipseckey.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord

MAX_IPSECKEY = 8

_GATEWAY_TYPE_MEANING = {
    0: "no gateway",
    1: "IPv4",
    2: "IPv6",
    3: "domain name",
}

# IANA IPSECKEY Algorithm Type (RFC 4025, RFC 8005, RFC 9373). Labels only.
_ALGORITHM_MEANING = {
    0: "no key",
    1: "DSA",
    2: "RSA",
    3: "ECDSA",
    4: "EdDSA",
}

IPSECKEY_NOTE = (
    "IPSECKEY (RFC 4025) publishes an IPsec gateway and a public key at this "
    "name. This tool lists precedence, gateway type, algorithm, gateway, and "
    "key length. It does not probe IPsec or IKE, does not dump key material, "
    "and does not resolve a gateway domain name. A missing IPSECKEY is common "
    "and is not a compromise. A published gateway is text in DNS, not an "
    "IPsec session this tool established."
)


@dataclass(frozen=True)
class IpseckeyRecord:
    precedence: int
    gateway_type: int
    gateway_type_meaning: str
    algorithm: int
    algorithm_meaning: str
    gateway: str
    key_length: int


@dataclass(frozen=True)
class IpseckeyObservation:
    status: str
    query_name: str
    ipseckeys: tuple[IpseckeyRecord, ...]
    truncated: bool = False
    note: str = IPSECKEY_NOTE
    error: str | None = None


def gateway_type_meaning(gateway_type: int) -> str:
    return _GATEWAY_TYPE_MEANING.get(gateway_type, "unknown gateway type")


def algorithm_meaning(algorithm: int) -> str:
    return _ALGORITHM_MEANING.get(algorithm, "unknown algorithm")


def normalize_gateway(gateway: object, gateway_type: int) -> str:
    """Format the published gateway. A domain name is stored, never followed."""
    if gateway_type == 0 or gateway in (None, "", "."):
        return "."
    text = str(gateway).strip()
    if gateway_type == 3:
        return text.rstrip(".").lower()
    if gateway_type in {1, 2}:
        try:
            return str(ipaddress.ip_address(text.rstrip(".")))
        except ValueError:
            return text
    return text.rstrip(".")


def key_length_of(key: object) -> int:
    """Byte length only. Key material is never returned."""
    if isinstance(key, (bytes, bytearray)):
        return len(key)
    return 0


def record_from_rdata(rdata: object) -> IpseckeyRecord:
    """Build one listing row from dnspython rdata. Key bytes are not kept."""
    precedence = int(getattr(rdata, "precedence", 0))
    gateway_type = int(getattr(rdata, "gateway_type", 0))
    algorithm = int(getattr(rdata, "algorithm", 0))
    gateway = normalize_gateway(getattr(rdata, "gateway", None), gateway_type)
    return IpseckeyRecord(
        precedence=precedence,
        gateway_type=gateway_type,
        gateway_type_meaning=gateway_type_meaning(gateway_type),
        algorithm=algorithm,
        algorithm_meaning=algorithm_meaning(algorithm),
        gateway=gateway,
        key_length=key_length_of(getattr(rdata, "key", b"")),
    )


def record_from_record(record: DNSRecord) -> IpseckeyRecord | None:
    """Parse one IPSECKEY row. The gateway name is stored, never resolved."""
    details = dict(record.details)
    parts = record.value.split()
    precedence = _int_field(details.get("Precedence"), parts, 0)
    gateway_type = _int_field(details.get("Gateway type"), parts, 1)
    algorithm = _int_field(details.get("Algorithm"), parts, 2)
    if precedence < 0 or gateway_type < 0 or algorithm < 0:
        return None
    labeled_gateway = details.get("Gateway")
    raw_gateway = labeled_gateway if labeled_gateway else (parts[3] if len(parts) > 3 else "")
    gateway = normalize_gateway(raw_gateway, gateway_type)
    if gateway_type != 0 and not gateway:
        return None
    return IpseckeyRecord(
        precedence=precedence,
        gateway_type=gateway_type,
        gateway_type_meaning=gateway_type_meaning(gateway_type),
        algorithm=algorithm,
        algorithm_meaning=algorithm_meaning(algorithm),
        gateway=gateway,
        key_length=_key_length_field(details.get("Key length"), parts),
    )


def evaluate_ipseckey(
    query_name: str,
    records: Sequence[DNSRecord],
    error: str | None = None,
    limit: int = MAX_IPSECKEY,
) -> IpseckeyObservation:
    """Map published IPSECKEY records to FOUND / NOT DETECTED. No IPsec probe."""
    parsed: list[IpseckeyRecord] = []
    seen: set[tuple[int, int, int, str]] = set()
    for record in records:
        item = record_from_record(record)
        if item is None:
            continue
        key = (item.precedence, item.gateway_type, item.algorithm, item.gateway)
        if key in seen:
            continue
        seen.add(key)
        parsed.append(item)
    parsed.sort(key=lambda item: (item.precedence, item.gateway_type, item.algorithm, item.gateway))
    truncated = len(parsed) > limit
    ipseckeys = tuple(parsed[:limit])
    host = query_name.rstrip(".").lower()
    if not ipseckeys:
        return IpseckeyObservation(
            status="NOT DETECTED",
            query_name=host,
            ipseckeys=(),
            truncated=False,
            error=error,
        )
    return IpseckeyObservation(
        status="FOUND",
        query_name=host,
        ipseckeys=ipseckeys,
        truncated=truncated,
        error=error,
    )


def format_ipseckey_value(rdata: object) -> str:
    """Stable listing text. Key bytes are never included."""
    item = record_from_rdata(rdata)
    return (
        f"{item.precedence} {item.gateway_type} {item.algorithm} "
        f"{item.gateway} key-length={item.key_length}"
    )


def ipseckey_details(rdata: object) -> tuple[tuple[str, str], ...]:
    item = record_from_rdata(rdata)
    return (
        ("Precedence", f"{item.precedence} — lower number is preferred"),
        (
            "Gateway type",
            f"{item.gateway_type} — {item.gateway_type_meaning}",
        ),
        ("Algorithm", f"{item.algorithm} — {item.algorithm_meaning}"),
        ("Gateway", item.gateway),
        ("Key length", str(item.key_length)),
        (
            "Note",
            "IPsec is not probed; key material is not dumped; a gateway "
            "domain name is not resolved (RFC 4025 listing only).",
        ),
    )


def _int_field(labeled: str | None, parts: list[str], index: int) -> int:
    if labeled:
        token = labeled.split("—", 1)[0].strip()
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
