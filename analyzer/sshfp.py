"""SSHFP host-key fingerprints at the queried hostname (RFC 4255).

SSHFP publishes SSH host-key fingerprints in DNS so a client can check
the key without a first-use prompt (typically with DNSSEC). This tool
only reads the DNS record. It does not open TCP/22 or compare live keys.

The record lives at the hostname itself, not under a service prefix.
Missing SSHFP is common and is not a compromise.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord

FP_HEX_MAX = 128

_ALGORITHM_MEANING = {
    1: "RSA",
    2: "DSS / DSA",
    3: "ECDSA",
    4: "Ed25519",
    6: "Ed448",
}
_FP_TYPE_MEANING = {
    1: "SHA-1",
    2: "SHA-256",
}

SSHFP_NOTE = (
    "SSHFP (RFC 4255) publishes SSH host-key fingerprints at this hostname. "
    "This is a DNS record, not an SSH scan. The tool does not open port 22 "
    "or compare live host keys. NOT DETECTED is common and is not a compromise. "
    "SSH clients that use VerifyHostKeyDNS also need DNSSEC validation."
)


@dataclass(frozen=True)
class SshfpFingerprint:
    algorithm: int
    fingerprint_type: int
    fingerprint: str
    fingerprint_truncated: bool
    algorithm_meaning: str
    fingerprint_type_meaning: str


@dataclass(frozen=True)
class SshfpObservation:
    status: str
    query_name: str
    fingerprints: tuple[SshfpFingerprint, ...]
    note: str = SSHFP_NOTE
    error: str | None = None


def evaluate_sshfp(
    query_name: str,
    records: Sequence[DNSRecord],
    error: str | None = None,
) -> SshfpObservation:
    """Interpret SSHFP answers at the queried hostname."""
    fingerprints = tuple(_fingerprint_from_record(item) for item in records)
    if not fingerprints:
        return SshfpObservation(
            status="NOT DETECTED",
            query_name=query_name,
            fingerprints=(),
            error=error,
        )
    return SshfpObservation(
        status="FOUND",
        query_name=query_name,
        fingerprints=fingerprints,
        error=error,
    )


def algorithm_meaning(algorithm: int) -> str:
    return _ALGORITHM_MEANING.get(algorithm, "unknown algorithm")


def fp_type_meaning(fingerprint_type: int) -> str:
    return _FP_TYPE_MEANING.get(fingerprint_type, "unknown fingerprint type")


def fingerprint_hex(fp: object) -> tuple[str, bool]:
    """Return lowercase hex and whether it was truncated."""
    if isinstance(fp, (bytes, bytearray)):
        raw = bytes(fp).hex()
    else:
        raw = str(fp).strip().replace(" ", "").lower()
    if len(raw) > FP_HEX_MAX:
        return raw[:FP_HEX_MAX], True
    return raw, False


def _fingerprint_from_record(record: DNSRecord) -> SshfpFingerprint:
    details = dict(record.details)
    parts = record.value.split()
    algorithm = _int_field(details.get("Algorithm"), parts, 0)
    fp_type = _int_field(details.get("Fingerprint type"), parts, 1)
    fingerprint = parts[2] if len(parts) > 2 else ""
    truncated = details.get("Truncated") == "yes"
    return SshfpFingerprint(
        algorithm=algorithm,
        fingerprint_type=fp_type,
        fingerprint=fingerprint,
        fingerprint_truncated=truncated,
        algorithm_meaning=algorithm_meaning(algorithm),
        fingerprint_type_meaning=fp_type_meaning(fp_type),
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
