"""SSHFP parsing tests. No network access."""

from unittest.mock import MagicMock

import dns.resolver

from analyzer.exceptions import DNSTimeoutError
from analyzer.models import DNSRecord
from analyzer.records import format_rdata, records_from_answer
from analyzer.resolver import DNSResolver
from analyzer.sshfp import FP_HEX_MAX, evaluate_sshfp


class SimpleAnswer:
    def __init__(self, *rdata: object, ttl: int = 300) -> None:
        self._rdata = rdata
        self.ttl = ttl

    def __iter__(self):
        return iter(self._rdata)


class DummyRdata:
    def __init__(self, **attrs: object) -> None:
        for key, value in attrs.items():
            setattr(self, key, value)


def _hash() -> bytes:
    return bytes.fromhex("ab" * 32)


def _record(value: str | None = None) -> DNSRecord:
    assoc = "ab" * 32
    text = value or f"4 2 {assoc}"
    parts = text.split()
    return DNSRecord(
        "SSHFP",
        "example.com",
        text,
        300,
        details=(
            ("Algorithm", f"{parts[0]} — Ed25519"),
            ("Fingerprint type", f"{parts[1]} — SHA-256"),
            ("Fingerprint", parts[2] if len(parts) > 2 else ""),
        ),
    )


def test_sshfp_not_detected() -> None:
    observation = evaluate_sshfp("example.com", [])
    assert observation.status == "NOT DETECTED"
    assert observation.fingerprints == ()
    assert observation.query_name == "example.com"


def test_sshfp_found() -> None:
    observation = evaluate_sshfp("example.com", [_record()])
    assert observation.status == "FOUND"
    item = observation.fingerprints[0]
    assert item.algorithm == 4
    assert item.fingerprint_type == 2
    assert item.fingerprint == "ab" * 32
    assert "Ed25519" in item.algorithm_meaning
    assert "SHA-256" in item.fingerprint_type_meaning


def test_sshfp_format_from_rdata() -> None:
    rdata = DummyRdata(algorithm=4, fp_type=2, fingerprint=_hash())
    assert format_rdata("SSHFP", rdata) == f"4 2 {_hash().hex()}"
    row = records_from_answer("SSHFP", "Example.COM.", SimpleAnswer(rdata, ttl=60))[0]
    assert row.name == "example.com"
    details = dict(row.details)
    assert "Ed25519" in details["Algorithm"]
    assert "Truncated" not in details


def test_sshfp_truncates_long_fingerprint() -> None:
    fp = bytes(range(256)) * 2
    rdata = DummyRdata(algorithm=1, fp_type=1, fingerprint=fp)
    text = format_rdata("SSHFP", rdata)
    hexpart = text.split()[-1]
    assert len(hexpart) == FP_HEX_MAX
    row = records_from_answer("SSHFP", "example.com", SimpleAnswer(rdata))[0]
    assert dict(row.details)["Truncated"] == "yes"
    observation = evaluate_sshfp("example.com", [row])
    assert observation.fingerprints[0].fingerprint_truncated is True


def test_inspect_sshfp_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._client = MagicMock()
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()

    observation = resolver.inspect_sshfp("example.com")

    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "example.com"


def test_inspect_sshfp_timeout_has_error() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_sshfp = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]

    observation = resolver.inspect_sshfp("example.com")

    assert observation.status == "NOT DETECTED"
    assert observation.error is not None


def test_inspect_sshfp_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    rdata = DummyRdata(algorithm=4, fp_type=2, fingerprint=_hash())
    resolver.resolve_sshfp = MagicMock(  # type: ignore[method-assign]
        return_value=records_from_answer("SSHFP", "example.com", SimpleAnswer(rdata))
    )
    observation = resolver.inspect_sshfp("example.com")
    assert observation.status == "FOUND"
    assert observation.fingerprints[0].algorithm == 4
    resolver.resolve_sshfp.assert_called_once_with("example.com")
