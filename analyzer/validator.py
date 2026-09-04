"""Domain input validation and normalization.

A URL is not a domain. A URL has a scheme, host, path, and optional query:

    https://www.example.com/login?next=/home
    |----|  |--------------| |----| |---------|
    scheme     hostname       path    query

DNS queries need only the hostname (often called the domain in this tool):

    www.example.com

This module accepts either form, extracts the hostname, and checks it against
practical DNS label rules. It does not send any DNS queries.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# LDH = letters, digits, hyphen. Underscores appear in service names
# (_dmarc, _domainkey) but not in a typical user-supplied target domain.
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_MAX_FQDN_LENGTH = 253


class DomainValidationError(ValueError):
    """Raised when input cannot be used as a DNS lookup target."""


def is_valid_domain(raw: str | None) -> bool:
    """Return True if normalize_domain() would succeed."""
    try:
        normalize_domain(raw)
        return True
    except DomainValidationError:
        return False


def normalize_domain(raw: str | None) -> str:
    """Return a lowercase FQDN suitable for later DNS queries.

    Accepts:
        example.com
        EXAMPLE.COM.
        subdomain.example.com
        http://example.com
        https://example.com/page?q=1

    Rejects:
        empty / whitespace-only input
        random characters
        bare TLDs or single labels (example)
        IP addresses (those belong to --reverse)
    """
    if raw is None:
        raise DomainValidationError("Domain cannot be empty.")

    if not isinstance(raw, str):
        raise DomainValidationError("Domain must be a string.")

    stripped = raw.strip()
    if not stripped:
        raise DomainValidationError("Domain cannot be empty.")

    hostname = _extract_hostname(stripped)
    hostname = hostname.strip(".").lower()

    if not hostname:
        raise DomainValidationError("Could not extract a hostname from the input.")

    if _is_ip_address(hostname):
        raise DomainValidationError(
            "Input looks like an IP address. Use --reverse <ip>."
        )

    _assert_allowed_characters(hostname)
    ascii_hostname = _to_ascii(hostname)
    _assert_fqdn(ascii_hostname)
    return ascii_hostname


def _extract_hostname(value: str) -> str:
    """Pull the host out of a URL, host:port, or bare domain."""
    candidate = value

    if "://" in candidate:
        parsed = urlparse(candidate)
        if not parsed.hostname:
            raise DomainValidationError("Could not parse a hostname from the URL.")
        return parsed.hostname

    for separator in ("/", "?", "#"):
        if separator in candidate:
            candidate = candidate.split(separator, 1)[0]

    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[-1]

    # example.com:443 — but not IPv6 literals such as 2001:db8::1
    if candidate.count(":") == 1:
        host, port = candidate.rsplit(":", 1)
        if port.isdigit():
            candidate = host

    if " " in candidate:
        raise DomainValidationError("Domain cannot contain spaces.")

    return candidate


def _assert_allowed_characters(hostname: str) -> None:
    """Reject punctuation before IDNA encoding (e.g. '!!!')."""
    if re.search(r"[^a-z0-9.\-\u00C0-\uFFFF]", hostname):
        raise DomainValidationError("Domain contains invalid characters.")


def _to_ascii(hostname: str) -> str:
    """Encode Internationalized Domain Names to Punycode (xn--...)."""
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DomainValidationError("Domain contains invalid characters.") from exc


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _assert_fqdn(hostname: str) -> None:
    if len(hostname) > _MAX_FQDN_LENGTH:
        raise DomainValidationError(
            f"Domain is too long (max {_MAX_FQDN_LENGTH} characters)."
        )

    labels = hostname.split(".")
    if len(labels) < 2:
        raise DomainValidationError(
            "A domain must include a top-level domain (e.g. example.com)."
        )

    if any(len(label) == 0 for label in labels):
        raise DomainValidationError("Domain contains an empty label.")

    for label in labels:
        if len(label) > 63:
            raise DomainValidationError("A domain label cannot exceed 63 characters.")
        if not _LABEL_RE.match(label):
            raise DomainValidationError(f"Invalid domain label: {label!r}.")

    tld = labels[-1]
    if tld.isdigit():
        raise DomainValidationError("The top-level domain cannot be all digits.")
    if len(tld) < 2:
        raise DomainValidationError("The top-level domain is too short.")
