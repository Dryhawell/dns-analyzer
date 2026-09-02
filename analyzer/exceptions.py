"""DNS query errors with user-facing messages.

dnspython raises its own exception types. We wrap them so the CLI never
depends on library names, and so tests can assert on stable classes.
"""

from __future__ import annotations


class DNSQueryError(Exception):
    """Base class for recoverable DNS query failures."""

    user_message = "DNS resolution error."

    def __str__(self) -> str:
        return self.user_message


class DomainNotFoundError(DNSQueryError):
    """The name does not exist (NXDOMAIN)."""

    user_message = "Domain does not exist."


class DNSTimeoutError(DNSQueryError):
    """Resolver did not answer within the configured timeout."""

    user_message = "DNS query timed out."


class NoNameserversError(DNSQueryError):
    """No usable nameservers, or they all returned a failure such as SERVFAIL."""

    user_message = "No nameservers available."


class DNSResolutionError(DNSQueryError):
    """Catch-all for other dnspython DNS exceptions."""

    user_message = "DNS resolution error."


class InvalidIPError(ValueError):
    """Raised when --reverse input is not an IPv4 or IPv6 address."""
