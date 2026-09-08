"""DANE TLSA parsing tests. No network access."""

from unittest.mock import MagicMock

import dns.resolver

from analyzer.exceptions import DNSTimeoutError
from analyzer.models import DNSRecord
from analyzer.records import format_rdata, records_from_answer
from analyzer.resolver import DNSResolver
from analyzer.tlsa import ASSOC_HEX_MAX, evaluate_tlsa, tlsa_query_name


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
    text = value or f"3 1 1 {assoc}"
    parts = text.split()
    return DNSRecord(
        "TLSA",
        "_443._tcp.example.com",
        text,
        300,
        details=(
            ("Usage", f"{parts[0]} — DANE-EE — domain-issued certificate (PKIX optional)"),
            ("Selector", f"{parts[1]} — SubjectPublicKeyInfo (SPKI)"),
            ("Matching", f"{parts[2]} — SHA-256"),
            ("Association", parts[3] if len(parts) > 3 else ""),
        ),
    )


def test_tlsa_query_name() -> None:
    assert tlsa_query_name("Example.COM") == "_443._tcp.example.com"


def test_tlsa_not_detected() -> None:
    observation = evaluate_tlsa("_443._tcp.example.com", [])
    assert observation.status == "NOT DETECTED"
    assert observation.associations == ()
    assert observation.port == 443
    assert observation.protocol == "tcp"


def test_tlsa_found() -> None:
    observation = evaluate_tlsa("_443._tcp.example.com", [_record()])
    assert observation.status == "FOUND"
    assert observation.query_name == "_443._tcp.example.com"
    item = observation.associations[0]
    assert item.usage == 3
    assert item.selector == 1
    assert item.matching_type == 1
    assert item.association == "ab" * 32
    assert "DANE-EE" in item.usage_meaning
    assert "SPKI" in item.selector_meaning
    assert "SHA-256" in item.matching_meaning


def test_tlsa_format_from_rdata() -> None:
    rdata = DummyRdata(usage=3, selector=1, mtype=1, cert=_hash())
    assert format_rdata("TLSA", rdata) == f"3 1 1 {_hash().hex()}"
    row = records_from_answer("TLSA", "_443._tcp.Example.COM.", SimpleAnswer(rdata, ttl=60))[0]
    assert row.name == "_443._tcp.example.com"
    details = dict(row.details)
    assert "DANE-EE" in details["Usage"]
    assert "Truncated" not in details


def test_tlsa_truncates_long_association() -> None:
    cert = bytes(range(256)) * 2
    rdata = DummyRdata(usage=0, selector=0, mtype=0, cert=cert)
    text = format_rdata("TLSA", rdata)
    hexpart = text.split()[-1]
    assert len(hexpart) == ASSOC_HEX_MAX
    row = records_from_answer("TLSA", "_443._tcp.example.com", SimpleAnswer(rdata))[0]
    assert dict(row.details)["Truncated"] == "yes"
    observation = evaluate_tlsa("_443._tcp.example.com", [row])
    assert observation.associations[0].association_truncated is True


def test_inspect_tlsa_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._client = MagicMock()
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()

    observation = resolver.inspect_tlsa("example.com")

    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "_443._tcp.example.com"


def test_inspect_tlsa_timeout_has_error() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_tlsa = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]

    observation = resolver.inspect_tlsa("example.com")

    assert observation.status == "NOT DETECTED"
    assert observation.error is not None


def test_inspect_tlsa_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    rdata = DummyRdata(usage=3, selector=1, mtype=1, cert=_hash())
    resolver.resolve_tlsa = MagicMock(  # type: ignore[method-assign]
        return_value=records_from_answer(
            "TLSA",
            "_443._tcp.example.com",
            SimpleAnswer(rdata),
        )
    )
    observation = resolver.inspect_tlsa("example.com")
    assert observation.status == "FOUND"
    assert observation.associations[0].usage == 3
    resolver.resolve_tlsa.assert_called_once_with("_443._tcp.example.com")
