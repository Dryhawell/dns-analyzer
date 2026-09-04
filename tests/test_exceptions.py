"""Stable exception messages. No network access."""

from analyzer.exceptions import (
    DNSNetworkError,
    DNSQueryError,
    DNSResolutionError,
    DNSTimeoutError,
    DomainNotFoundError,
    InvalidIPError,
    NoNameserversError,
    ResolverConfigError,
)


def test_user_messages_are_stable() -> None:
    assert str(DomainNotFoundError()) == "Domain does not exist."
    assert str(DNSTimeoutError()) == "DNS query timed out."
    assert str(NoNameserversError()) == "No nameservers available."
    assert str(DNSResolutionError()) == "DNS resolution error."
    assert str(DNSNetworkError()) == "Network error while querying DNS."
    assert str(DNSQueryError()) == "DNS resolution error."


def test_timeout_is_a_query_error() -> None:
    assert issubclass(DNSTimeoutError, DNSQueryError)
    assert issubclass(DomainNotFoundError, DNSQueryError)
    assert issubclass(DNSNetworkError, DNSQueryError)
    assert not issubclass(InvalidIPError, DNSQueryError)
    assert not issubclass(ResolverConfigError, DNSQueryError)
