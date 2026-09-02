"""Convert dnspython rdata objects into plain strings."""

from __future__ import annotations

import ipaddress

from analyzer.models import DNSRecord


def format_rdata(record_type: str, rdata: object) -> str:
    """Return a stable, human-readable value for one resource record.

    Type-specific fields (MX preference, SOA serial, CAA tags) are kept
    because later phases will parse them. Trailing dots are stripped so
    CLI output matches the normalized domain style.
    """
    rtype = record_type.upper()

    if rtype == "MX":
        return _text(getattr(rdata, "exchange", rdata))

    if rtype == "TXT":
        strings = getattr(rdata, "strings", None)
        if strings is None:
            return _text(rdata)
        parts: list[str] = []
        for part in strings:
            if isinstance(part, bytes):
                parts.append(part.decode("utf-8", errors="replace"))
            else:
                parts.append(str(part))
        return "".join(parts)

    if rtype == "SOA":
        mname = _text(getattr(rdata, "mname", ""))
        rname = _text(getattr(rdata, "rname", ""))
        serial = getattr(rdata, "serial", "")
        return f"{mname} {rname} serial={serial}"

    if rtype == "CAA":
        flags = getattr(rdata, "flags", "")
        tag = getattr(rdata, "tag", "")
        if isinstance(tag, bytes):
            tag = tag.decode("ascii", errors="replace")
        value = getattr(rdata, "value", "")
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        return f'{flags} {tag} "{value}"'

    if rtype in {"A", "AAAA"}:
        return canonicalize_ip(_text(rdata))

    return _text(rdata)


def records_from_answer(record_type: str, queried_name: str, answer: object) -> list[DNSRecord]:
    """Build DNSRecord rows from a dnspython Answer."""
    ttl = int(getattr(answer, "ttl", 0) or 0)
    name = queried_name.rstrip(".").lower()
    records: list[DNSRecord] = []
    for rdata in answer:  # type: ignore[not-iterable]
        records.append(
            DNSRecord(
                record_type=record_type.upper(),
                name=name,
                value=format_rdata(record_type, rdata),
                ttl=ttl,
                priority=_mx_priority(record_type, rdata),
            )
        )
    return records


def _mx_priority(record_type: str, rdata: object) -> int | None:
    if record_type.upper() != "MX":
        return None
    preference = getattr(rdata, "preference", None)
    if preference is None:
        return None
    return int(preference)


def canonicalize_ip(value: str) -> str:
    """Normalize A/AAAA rdata (compress IPv6, keep dotted IPv4)."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def describe_ip_scope(value: str) -> str | None:
    """Return a non-global scope label, or None for typical public unicast.

    Missing AAAA or a private address is an observation, not a verdict.
    """
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return "invalid"

    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private:
        return "private"
    if addr.is_reserved:
        return "reserved"
    return None


def _text(value: object) -> str:
    return str(value).rstrip(".")
