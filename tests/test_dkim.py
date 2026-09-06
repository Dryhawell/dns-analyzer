"""DKIM selector parsing tests. No network access."""

from unittest.mock import MagicMock

import dns.resolver
import pytest

from analyzer.dkim import (
    MAX_SELECTORS,
    DkimSelectorError,
    dkim_query_name,
    evaluate_dkim,
    normalize_selector,
    normalize_selectors,
)
from analyzer.exceptions import DNSTimeoutError
from analyzer.models import DNSRecord
from analyzer.resolver import DNSResolver


def _txt(value: str, name: str = "google._domainkey.example.com") -> list[DNSRecord]:
    return [DNSRecord("TXT", name, value, 300)]


def test_dkim_query_name() -> None:
    assert dkim_query_name("Example.COM", "Google") == "google._domainkey.example.com"


def test_normalize_selector_accepts_dotted_labels() -> None:
    assert normalize_selector(" S1 ") == "s1"
    assert normalize_selector("mail.google") == "mail.google"


def test_normalize_selector_rejects_junk() -> None:
    with pytest.raises(DkimSelectorError, match="empty"):
        normalize_selector("  ")
    with pytest.raises(DkimSelectorError, match="Invalid"):
        normalize_selector("*.google")
    with pytest.raises(DkimSelectorError, match="Invalid"):
        normalize_selector("foo bar")


def test_normalize_selectors_dedupes_and_caps() -> None:
    assert normalize_selectors(["google", "Google", "s1"]) == ("google", "s1")
    too_many = [f"s{i}" for i in range(MAX_SELECTORS + 1)]
    with pytest.raises(DkimSelectorError, match="Too many"):
        normalize_selectors(too_many)


def test_dkim_not_detected() -> None:
    observation = evaluate_dkim("google._domainkey.example.com", "google", [])
    assert observation.status == "NOT DETECTED"
    assert observation.key_present is False
    assert observation.revoked is False


def test_dkim_found_rsa() -> None:
    observation = evaluate_dkim(
        "google._domainkey.example.com",
        "google",
        _txt("v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"),
    )
    assert observation.status == "FOUND"
    assert observation.key_type == "rsa"
    assert observation.key_present is True
    assert observation.key_chars > 10
    assert observation.revoked is False


def test_dkim_default_key_type_is_rsa() -> None:
    observation = evaluate_dkim(
        "s1._domainkey.example.com",
        "s1",
        _txt("v=DKIM1; p=abc"),
    )
    assert observation.key_type == "rsa"
    assert observation.status == "FOUND"


def test_dkim_empty_p_is_revoked() -> None:
    observation = evaluate_dkim(
        "google._domainkey.example.com",
        "google",
        _txt("v=DKIM1; p="),
    )
    assert observation.status == "REVOKED"
    assert observation.revoked is True
    assert observation.key_present is False


def test_dkim_ignores_whitespace_in_public_key() -> None:
    observation = evaluate_dkim(
        "s1._domainkey.example.com",
        "s1",
        _txt("v=DKIM1; p=MI IB"),
    )
    assert observation.key_chars == 4
    assert observation.status == "FOUND"


def test_dkim_requires_version_tag() -> None:
    observation = evaluate_dkim(
        "google._domainkey.example.com",
        "google",
        _txt("k=rsa; p=abc"),
    )
    assert observation.status == "NOT DETECTED"


def test_multiple_dkim_records() -> None:
    name = "google._domainkey.example.com"
    observation = evaluate_dkim(
        name,
        "google",
        _txt("v=DKIM1; p=aaa", name) + _txt("v=DKIM1; p=bbb", name),
    )
    assert observation.multiple_records is True
    assert observation.status == "FOUND"


def test_inspect_dkim_nxdomain_is_not_detected() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._client = MagicMock()
    resolver._client.resolve.side_effect = dns.resolver.NXDOMAIN()

    observation = resolver.inspect_dkim("example.com", "google")

    assert observation.status == "NOT DETECTED"
    assert observation.query_name == "google._domainkey.example.com"


def test_inspect_dkim_timeout_is_not_detected_with_error() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_txt = MagicMock(side_effect=DNSTimeoutError())  # type: ignore[method-assign]

    observation = resolver.inspect_dkim("example.com", "google")

    assert observation.status == "NOT DETECTED"
    assert observation.error is not None


def test_inspect_dkim_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver.resolve_txt = MagicMock(  # type: ignore[method-assign]
        return_value=_txt("v=DKIM1; p=MIIB")
    )
    observation = resolver.inspect_dkim("example.com", "google")
    assert observation.status == "FOUND"
    resolver.resolve_txt.assert_called_once_with("google._domainkey.example.com")
