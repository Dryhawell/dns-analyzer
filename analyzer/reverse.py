"""Forward DNS vs reverse DNS helpers.

Forward DNS (A / AAAA): hostname → IP
Reverse DNS (PTR):      IP → hostname

The PTR query is not sent to the IP itself. The address is rewritten as a
name under in-addr.arpa (IPv4) or ip6.arpa (IPv6), then queried like any
other DNS name. Python's ipaddress module already builds that name.
"""

from __future__ import annotations

import ipaddress

from analyzer.exceptions import InvalidIPError


def parse_ip(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse a dotted IPv4 or textual IPv6 address."""
    if raw is None or not str(raw).strip():
        raise InvalidIPError("IP address cannot be empty.")
    try:
        return ipaddress.ip_address(raw.strip())
    except ValueError as exc:
        raise InvalidIPError("Invalid IP address. Use IPv4 or IPv6 (e.g. 8.8.8.8).") from exc


def ptr_name(raw: str) -> str:
    """Return the reverse zone name, e.g. 8.8.8.8 → 8.8.8.8.in-addr.arpa."""
    return parse_ip(raw).reverse_pointer


def looks_like_ip(raw: str | None) -> bool:
    if raw is None:
        return False
    try:
        ipaddress.ip_address(raw.strip())
        return True
    except ValueError:
        return False
