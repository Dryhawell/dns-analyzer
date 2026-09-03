"""Tests for reverse DNS (PTR) name construction. No network access."""

import pytest

from analyzer.exceptions import InvalidIPError
from analyzer.reverse import looks_like_ip, ptr_name


def test_ipv4_ptr_name_reverses_octets() -> None:
    assert ptr_name("1.2.3.4") == "4.3.2.1.in-addr.arpa"
    assert ptr_name("8.8.8.8") == "8.8.8.8.in-addr.arpa"


def test_ipv6_ptr_name_uses_ip6_arpa() -> None:
    name = ptr_name("2001:4860:4860::8888")
    assert name.endswith(".ip6.arpa")
    assert name.startswith("8.8.8.8.")


def test_invalid_ip_raises() -> None:
    with pytest.raises(InvalidIPError):
        ptr_name("example.com")
    with pytest.raises(InvalidIPError):
        ptr_name("")


def test_looks_like_ip() -> None:
    assert looks_like_ip("8.8.8.8") is True
    assert looks_like_ip("2001:db8::1") is True
    assert looks_like_ip(" example.com ") is False
    assert looks_like_ip("example.com") is False
