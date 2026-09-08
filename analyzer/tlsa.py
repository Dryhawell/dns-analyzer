"""DANE TLSA discovery at _443._tcp.<domain> (RFC 6698).

TLSA publishes a certificate association in DNS so a client can check a
TLS certificate without (or in addition to) the public CA system. This
tool only reads the DNS record. It does not open TCP/443, does not
follow MX, and does not guess www.

Port 443 / tcp is the well-known HTTPS name. Other ports are not queried.
Missing TLSA is common and is not a compromise.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord

DEFAULT_PORT = 443
DEFAULT_PROTOCOL = "tcp"
ASSOC_HEX_MAX = 128

_USAGE_MEANING = {
    0: "PKIX-TA — CA constraint (PKIX validation still required)",
    1: "PKIX-EE — EE certificate constraint (PKIX validation still required)",
    2: "DANE-TA — trust anchor advertised in DNS",
    3: "DANE-EE — domain-issued certificate (PKIX optional)",
}
_SELECTOR_MEANING = {
    0: "full certificate",
    1: "SubjectPublicKeyInfo (SPKI)",
}
_MATCHING_MEANING = {
    0: "exact match",
    1: "SHA-256",
    2: "SHA-512",
}

TLSA_NOTE = (
    "DANE TLSA (RFC 6698) publishes a certificate association at "
    "_443._tcp.<domain>. This is a DNS record, not a TLS scan. "
    "The tool does not open port 443 or compare the live certificate. "
    "NOT DETECTED is common and is not a compromise."
)


@dataclass(frozen=True)
class TlsaAssociation:
    usage: int
    selector: int
    matching_type: int
    association: str
    association_truncated: bool
    usage_meaning: str
    selector_meaning: str
    matching_meaning: str


@dataclass(frozen=True)
class TlsaObservation:
    status: str
    query_name: str
    port: int
    protocol: str
    associations: tuple[TlsaAssociation, ...]
    note: str = TLSA_NOTE
    error: str | None = None


def tlsa_query_name(
    domain: str,
    port: int = DEFAULT_PORT,
    protocol: str = DEFAULT_PROTOCOL,
) -> str:
    host = domain.rstrip(".").lower()
    return f"_{port}._{protocol}.{host}"


def evaluate_tlsa(
    query_name: str,
    records: Sequence[DNSRecord],
    error: str | None = None,
    port: int = DEFAULT_PORT,
    protocol: str = DEFAULT_PROTOCOL,
) -> TlsaObservation:
    """Interpret TLSA answers at _<port>._<protocol>.<domain>."""
    associations = tuple(_association_from_record(item) for item in records)
    if not associations:
        return TlsaObservation(
            status="NOT DETECTED",
            query_name=query_name,
            port=port,
            protocol=protocol,
            associations=(),
            error=error,
        )
    return TlsaObservation(
        status="FOUND",
        query_name=query_name,
        port=port,
        protocol=protocol,
        associations=associations,
        error=error,
    )


def usage_meaning(usage: int) -> str:
    return _USAGE_MEANING.get(usage, "unknown usage")


def selector_meaning(selector: int) -> str:
    return _SELECTOR_MEANING.get(selector, "unknown selector")


def matching_meaning(matching_type: int) -> str:
    return _MATCHING_MEANING.get(matching_type, "unknown matching type")


def association_hex(cert: object) -> tuple[str, bool]:
    """Return lowercase hex and whether it was truncated."""
    if isinstance(cert, (bytes, bytearray)):
        raw = bytes(cert).hex()
    else:
        raw = str(cert).strip().replace(" ", "").lower()
    if len(raw) > ASSOC_HEX_MAX:
        return raw[:ASSOC_HEX_MAX], True
    return raw, False


def _association_from_record(record: DNSRecord) -> TlsaAssociation:
    details = dict(record.details)
    parts = record.value.split()
    usage = _int_field(details.get("Usage"), parts, 0)
    selector = _int_field(details.get("Selector"), parts, 1)
    matching_type = _int_field(details.get("Matching"), parts, 2)
    assoc = parts[3] if len(parts) > 3 else ""
    truncated = details.get("Truncated") == "yes"
    return TlsaAssociation(
        usage=usage,
        selector=selector,
        matching_type=matching_type,
        association=assoc,
        association_truncated=truncated,
        usage_meaning=usage_meaning(usage),
        selector_meaning=selector_meaning(selector),
        matching_meaning=matching_meaning(matching_type),
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
