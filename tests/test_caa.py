"""CAA property summary tests. No network access."""

from unittest.mock import MagicMock

from analyzer.caa import evaluate_caa, property_from_record, tag_meaning
from analyzer.exceptions import DNSTimeoutError, DomainNotFoundError
from analyzer.models import DNSRecord
from analyzer.resolver import DNSResolver


def _caa(
    value: str,
    *,
    flags: int | None = None,
    tag: str | None = None,
) -> DNSRecord:
    details: tuple[tuple[str, str], ...] = ()
    if tag is not None:
        details = (("Tag", f"{tag} — {tag_meaning(tag)}"),)
    return DNSRecord("CAA", "example.com", value, 3600, details=details)


def test_tag_meaning_covers_rfc8659_properties() -> None:
    assert "issue certificates" in tag_meaning("issue")
    assert "wildcard" in tag_meaning("issuewild")
    assert "incident" in tag_meaning("iodef")
    assert tag_meaning("unknown") == "unknown CAA property"


def test_property_from_record_parses_quoted_value() -> None:
    item = property_from_record(_caa('0 issue "letsencrypt.org"'))
    assert item is not None
    assert item.flags == 0
    assert item.issuer_critical is False
    assert item.tag == "issue"
    assert item.value == "letsencrypt.org"
    assert "issue certificates" in item.tag_meaning


def test_property_from_record_issuer_critical_flag() -> None:
    item = property_from_record(_caa('128 issuewild "pki.goog"'))
    assert item is not None
    assert item.flags == 128
    assert item.issuer_critical is True
    assert item.tag == "issuewild"
    assert item.value == "pki.goog"


def test_evaluate_caa_lists_issue_issuewild_iodef() -> None:
    observation = evaluate_caa(
        "example.com",
        [
            _caa('0 issue "letsencrypt.org"'),
            _caa('0 issuewild "letsencrypt.org"'),
            _caa('0 iodef "mailto:caa@example.com"'),
        ],
    )
    assert observation.status == "FOUND"
    assert observation.issue == ("letsencrypt.org",)
    assert observation.issuewild == ("letsencrypt.org",)
    assert observation.iodef == ("mailto:caa@example.com",)
    assert len(observation.properties) == 3


def test_evaluate_caa_deny_all_is_found_not_compromise() -> None:
    observation = evaluate_caa("example.com", [_caa('0 issue ";"')])
    assert observation.status == "FOUND"
    assert observation.issue == (";",)
    assert ";" in observation.note


def test_evaluate_caa_not_detected() -> None:
    observation = evaluate_caa("www.example.com", ())
    assert observation.status == "NOT DETECTED"
    assert observation.properties == ()


def test_evaluate_caa_timeout_is_unreadable() -> None:
    observation = evaluate_caa(
        "example.com", (), error="DNS query timed out."
    )
    assert observation.status == "UNREADABLE"
    assert observation.error == "DNS query timed out."


def test_evaluate_caa_truncates_after_eight() -> None:
    records = [_caa(f'0 issue "ca{index}.example"') for index in range(9)]
    observation = evaluate_caa("example.com", records)
    assert observation.truncated is True
    assert len(observation.properties) == 8
    assert observation.issue[0] == "ca0.example"
    assert "ca8.example" not in observation.issue


def test_evaluate_caa_unknown_tag_is_listed() -> None:
    observation = evaluate_caa(
        "example.com",
        [_caa('0 contactemail "admin@example.com"')],
    )
    assert observation.status == "FOUND"
    assert observation.properties[0].tag == "contactemail"
    assert observation.properties[0].tag_meaning == "unknown CAA property"
    assert observation.issue == ()


def test_inspect_caa_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_caa = MagicMock(  # type: ignore[method-assign]
        return_value=[_caa('0 issue "letsencrypt.org"')]
    )
    observation = resolver.inspect_caa("example.com")
    assert observation.status == "FOUND"
    assert observation.issue == ("letsencrypt.org",)
    resolver.resolve_caa.assert_called_once_with("example.com")


def test_inspect_caa_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_caa = MagicMock(side_effect=DomainNotFoundError())  # type: ignore[method-assign]
    observation = resolver.inspect_caa("www.example.com")
    assert observation.status == "NOT DETECTED"


def test_inspect_caa_timeout_is_unreadable() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_caa = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]
    observation = resolver.inspect_caa("example.com")
    assert observation.status == "UNREADABLE"
