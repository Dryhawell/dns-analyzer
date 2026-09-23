"""CERT listing for a caller-supplied name (RFC 4398).

CERT publishes a certificate or CRL (or a URL/OID pointer) in DNS. This
tool only lists type, key tag, algorithm, and certificate length. It does
not dump certificate bytes, does not validate PKIX, does not fetch HTTP
URLs from type URI, and does not contact CAs.

Missing CERT is common and is not a compromise. Default scans do not
query CERT; pass --cert. Listing is not TLSA, not CAA, and not proof
that a TLS certificate lives in DNS.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.dnssec import algorithm_meaning
from analyzer.models import DNSRecord

MAX_CERT = 8

# IANA Certificate Types (RFC 4398). Labels only; bytes are not dumped.
_CERT_TYPE_MEANING = {
    1: "PKIX",
    2: "SPKI",
    3: "PGP",
    4: "IPKIX",
    5: "ISPKI",
    6: "IPGP",
    7: "ACPKIX",
    8: "IACPKIX",
    253: "URI",
    254: "OID",
}

CERT_NOTE = (
    "CERT (RFC 4398) publishes a certificate or CRL (or a URL/OID pointer) "
    "at this name. This tool lists type, key tag, algorithm, and certificate "
    "length. It does not dump certificate or CRL bytes, does not validate "
    "PKIX, does not fetch HTTP URLs from type URI, and does not contact CAs. "
    "A missing CERT is common and is not a compromise. Listing a record is "
    "not proof that a TLS certificate is in DNS, and it is not a replacement "
    "for CAA or TLSA."
)


@dataclass(frozen=True)
class CertRecord:
    cert_type: int
    cert_type_meaning: str
    key_tag: int
    algorithm: int
    algorithm_meaning: str
    cert_length: int


@dataclass(frozen=True)
class CertObservation:
    status: str
    query_name: str
    certs: tuple[CertRecord, ...]
    truncated: bool = False
    note: str = CERT_NOTE
    error: str | None = None


def cert_type_meaning(cert_type: int) -> str:
    return _CERT_TYPE_MEANING.get(cert_type, "unknown certificate type")


def cert_length_of(certificate: object) -> int:
    """Byte length only. Certificate or CRL material is never returned."""
    if isinstance(certificate, (bytes, bytearray)):
        return len(certificate)
    return 0


def record_from_rdata(rdata: object) -> CertRecord:
    """Build one listing row from dnspython rdata. Certificate bytes are not kept."""
    cert_type = int(getattr(rdata, "certificate_type", 0))
    key_tag = int(getattr(rdata, "key_tag", 0))
    algorithm = int(getattr(rdata, "algorithm", 0))
    return CertRecord(
        cert_type=cert_type,
        cert_type_meaning=cert_type_meaning(cert_type),
        key_tag=key_tag,
        algorithm=algorithm,
        algorithm_meaning=algorithm_meaning(algorithm),
        cert_length=cert_length_of(getattr(rdata, "certificate", b"")),
    )


def record_from_record(record: DNSRecord) -> CertRecord | None:
    """Parse one CERT row. Certificate bytes are not stored."""
    details = dict(record.details)
    parts = record.value.split()
    cert_type = _int_field(details.get("Certificate type"), parts, 0)
    key_tag = _int_field(details.get("Key tag"), parts, 1)
    algorithm = _int_field(details.get("Algorithm"), parts, 2)
    if cert_type < 0 or key_tag < 0 or algorithm < 0:
        return None
    return CertRecord(
        cert_type=cert_type,
        cert_type_meaning=cert_type_meaning(cert_type),
        key_tag=key_tag,
        algorithm=algorithm,
        algorithm_meaning=algorithm_meaning(algorithm),
        cert_length=_cert_length_field(details.get("Certificate length"), parts),
    )


def evaluate_cert(
    query_name: str,
    records: Sequence[DNSRecord],
    error: str | None = None,
    limit: int = MAX_CERT,
) -> CertObservation:
    """Map published CERT records to FOUND / NOT DETECTED. No PKIX check."""
    parsed: list[CertRecord] = []
    seen: set[tuple[int, int, int, int]] = set()
    for record in records:
        item = record_from_record(record)
        if item is None:
            continue
        key = (item.cert_type, item.key_tag, item.algorithm, item.cert_length)
        if key in seen:
            continue
        seen.add(key)
        parsed.append(item)
    parsed.sort(
        key=lambda item: (
            item.cert_type,
            item.key_tag,
            item.algorithm,
            item.cert_length,
        )
    )
    truncated = len(parsed) > limit
    certs = tuple(parsed[:limit])
    host = query_name.rstrip(".").lower()
    if not certs:
        return CertObservation(
            status="NOT DETECTED",
            query_name=host,
            certs=(),
            truncated=False,
            error=error,
        )
    return CertObservation(
        status="FOUND",
        query_name=host,
        certs=certs,
        truncated=truncated,
        error=error,
    )


def format_cert_value(rdata: object) -> str:
    """Stable listing text. Certificate bytes are never included."""
    item = record_from_rdata(rdata)
    return (
        f"{item.cert_type} {item.key_tag} {item.algorithm} "
        f"cert-length={item.cert_length}"
    )


def cert_details(rdata: object) -> tuple[tuple[str, str], ...]:
    item = record_from_rdata(rdata)
    return (
        ("Certificate type", f"{item.cert_type} — {item.cert_type_meaning}"),
        ("Key tag", str(item.key_tag)),
        ("Algorithm", f"{item.algorithm} — {item.algorithm_meaning}"),
        ("Certificate length", str(item.cert_length)),
        (
            "Note",
            "PKIX is not validated; certificate bytes are not dumped; "
            "type URI/OID pointers are not fetched; CERT is not TLSA or "
            "CAA (RFC 4398 listing only).",
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


def _cert_length_field(labeled: str | None, parts: list[str]) -> int:
    if labeled:
        token = str(labeled).split()[0]
        try:
            return int(token)
        except ValueError:
            pass
    for part in parts:
        if part.startswith("cert-length="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return 0
    return 0
