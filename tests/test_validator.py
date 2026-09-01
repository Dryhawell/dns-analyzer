"""Unit tests for domain validation. No network access required."""

import pytest

from analyzer.validator import DomainValidationError, is_valid_domain, normalize_domain


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("GOOGLE.COM", "google.com"),
        ("example.com.", "example.com"),
        ("  example.com  ", "example.com"),
        ("subdomain.example.com", "subdomain.example.com"),
        ("www.example.co.uk", "www.example.co.uk"),
        ("http://example.com", "example.com"),
        ("https://example.com", "example.com"),
        ("https://example.com/page", "example.com"),
        ("https://www.example.com/login?next=/home", "www.example.com"),
        ("http://example.com:8080/path", "example.com"),
        ("example.com/page", "example.com"),
        ("example.com:443", "example.com"),
    ],
)
def test_normalize_valid_domains(raw: str, expected: str) -> None:
    assert normalize_domain(raw) == expected
    assert is_valid_domain(raw) is True


def test_idn_encoded_to_punycode() -> None:
    assert normalize_domain("münchen.de") == "xn--mnchen-3ya.de"


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "   ",
        "http://",
        "https:///missing-host",
        "not a domain",
        "!!!",
        "example",
        ".com",
        "example..com",
        "-example.com",
        "example-.com",
        "8.8.8.8",
        "2001:db8::1",
        "http://127.0.0.1/",
    ],
)
def test_reject_invalid_input(raw: str | None) -> None:
    with pytest.raises(DomainValidationError):
        normalize_domain(raw)
    assert is_valid_domain(raw) is False


def test_error_message_for_empty_input() -> None:
    with pytest.raises(DomainValidationError, match="empty"):
        normalize_domain("")


def test_error_message_for_ip() -> None:
    with pytest.raises(DomainValidationError, match="IP address"):
        normalize_domain("1.1.1.1")


def test_error_message_for_garbage() -> None:
    with pytest.raises(DomainValidationError, match="invalid characters"):
        normalize_domain("!!!")
