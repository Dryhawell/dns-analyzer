"""Convert dnspython rdata objects into plain strings."""

from __future__ import annotations

import ipaddress

from analyzer.models import DNSRecord
from analyzer.naptr import flags_meaning
from analyzer.uri import scheme_meaning, uri_scheme
from analyzer.rrsig import format_rrsig_value, rrsig_details
from analyzer.ipseckey import format_ipseckey_value, ipseckey_details
from analyzer.cert import format_cert_value, cert_details
from analyzer.smimea import format_smimea_value, smimea_details
from analyzer.openpgpkey import format_openpgpkey_value, openpgpkey_details
from analyzer.sshfp import algorithm_meaning, fingerprint_hex, fp_type_meaning
from analyzer.tlsa import (
    association_hex,
    matching_meaning,
    selector_meaning,
    usage_meaning,
)


def format_rdata(record_type: str, rdata: object) -> str:
    """Return a stable, human-readable value for one resource record.

    Type-specific fields (MX preference, SOA serial, CAA tags) are kept
    on DNSRecord so the CLI and JSON can show them. Trailing dots are
    stripped so CLI output matches the normalized domain style.
    """
    rtype = record_type.upper()

    if rtype == "MX":
        return _text(getattr(rdata, "exchange", rdata))

    if rtype == "SRV":
        return _format_srv(rdata)

    if rtype == "NAPTR":
        return _format_naptr(rdata)

    if rtype == "URI":
        return _format_uri(rdata)

    if rtype == "DNAME":
        return _text(getattr(rdata, "target", rdata))

    if rtype == "IPSECKEY":
        return format_ipseckey_value(rdata)

    if rtype == "CERT":
        return format_cert_value(rdata)

    if rtype == "SMIMEA":
        return format_smimea_value(rdata)

    if rtype == "OPENPGPKEY":
        return format_openpgpkey_value(rdata)

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
        serial = getattr(rdata, "serial", "")
        return f"{mname} serial={serial}"

    if rtype == "CAA":
        flags = getattr(rdata, "flags", "")
        tag = getattr(rdata, "tag", "")
        if isinstance(tag, bytes):
            tag = tag.decode("ascii", errors="replace")
        value = getattr(rdata, "value", "")
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        return f'{flags} {tag} "{value}"'

    if rtype in {"HTTPS", "SVCB"}:
        return _format_svcb(rdata)

    if rtype == "TLSA":
        return _format_tlsa(rdata)

    if rtype == "SSHFP":
        return _format_sshfp(rdata)

    if rtype == "RRSIG":
        return format_rrsig_value(rdata)

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
                details=_record_details(record_type, rdata),
            )
        )
    return records


def _record_details(record_type: str, rdata: object) -> tuple[tuple[str, str], ...]:
    rtype = record_type.upper()
    if rtype == "SOA":
        return (
            ("Primary NS", _text(getattr(rdata, "mname", ""))),
            ("Mailbox", _text(getattr(rdata, "rname", ""))),
            ("Serial", str(getattr(rdata, "serial", ""))),
            ("Refresh", str(getattr(rdata, "refresh", ""))),
            ("Retry", str(getattr(rdata, "retry", ""))),
            ("Expire", str(getattr(rdata, "expire", ""))),
            ("Minimum", str(getattr(rdata, "minimum", ""))),
        )
    if rtype == "SRV":
        return _srv_details(rdata)
    if rtype == "NAPTR":
        return _naptr_details(rdata)
    if rtype == "URI":
        return _uri_details(rdata)
    if rtype == "RRSIG":
        return rrsig_details(rdata)
    if rtype == "DNAME":
        target = _text(getattr(rdata, "target", rdata))
        return (
            ("Target", target),
            (
                "Note",
                "DNAME redirects a subtree; this tool does not synthesize CNAME "
                "or walk names under this node.",
            ),
        )
    if rtype == "IPSECKEY":
        return ipseckey_details(rdata)
    if rtype == "CERT":
        return cert_details(rdata)
    if rtype == "SMIMEA":
        return smimea_details(rdata)
    if rtype == "OPENPGPKEY":
        return openpgpkey_details(rdata)
    if rtype == "CAA":
        tag = getattr(rdata, "tag", "")
        if isinstance(tag, bytes):
            tag = tag.decode("ascii", errors="replace")
        meaning = {
            "issue": "allows this CA to issue certificates",
            "issuewild": "allows this CA to issue wildcard certificates",
            "iodef": "incident report URI",
        }.get(str(tag), "")
        if meaning:
            return (("Tag", f"{tag} — {meaning}"),)
        return ()
    if rtype in {"HTTPS", "SVCB"}:
        return _svcb_details(rdata)
    if rtype == "TLSA":
        return _tlsa_details(rdata)
    if rtype == "SSHFP":
        return _sshfp_details(rdata)
    return ()


def _mx_priority(record_type: str, rdata: object) -> int | None:
    rtype = record_type.upper()
    if rtype == "MX":
        preference = getattr(rdata, "preference", None)
        if preference is None:
            return None
        return int(preference)
    if rtype in {"HTTPS", "SVCB", "SRV", "URI"}:
        priority = getattr(rdata, "priority", None)
        if priority is None:
            return None
        return int(priority)
    if rtype == "NAPTR":
        order = getattr(rdata, "order", None)
        if order is None:
            return None
        return int(order)
    return None


def _format_tlsa(rdata: object) -> str:
    usage = int(getattr(rdata, "usage", 0))
    selector = int(getattr(rdata, "selector", 0))
    matching_type = int(getattr(rdata, "mtype", 0))
    assoc, _truncated = association_hex(getattr(rdata, "cert", b""))
    return f"{usage} {selector} {matching_type} {assoc}"


def _tlsa_details(rdata: object) -> tuple[tuple[str, str], ...]:
    usage = int(getattr(rdata, "usage", -1))
    selector = int(getattr(rdata, "selector", -1))
    matching_type = int(getattr(rdata, "mtype", -1))
    assoc, truncated = association_hex(getattr(rdata, "cert", b""))
    rows: list[tuple[str, str]] = [
        ("Usage", f"{usage} — {usage_meaning(usage)}"),
        ("Selector", f"{selector} — {selector_meaning(selector)}"),
        ("Matching", f"{matching_type} — {matching_meaning(matching_type)}"),
        ("Association", assoc),
    ]
    if truncated:
        rows.append(("Truncated", "yes"))
    return tuple(rows)


def _format_sshfp(rdata: object) -> str:
    algorithm = int(getattr(rdata, "algorithm", 0))
    fp_type = int(getattr(rdata, "fp_type", 0))
    fingerprint, _truncated = fingerprint_hex(getattr(rdata, "fingerprint", b""))
    return f"{algorithm} {fp_type} {fingerprint}"


def _sshfp_details(rdata: object) -> tuple[tuple[str, str], ...]:
    algorithm = int(getattr(rdata, "algorithm", -1))
    fp_type = int(getattr(rdata, "fp_type", -1))
    fingerprint, truncated = fingerprint_hex(getattr(rdata, "fingerprint", b""))
    rows: list[tuple[str, str]] = [
        ("Algorithm", f"{algorithm} — {algorithm_meaning(algorithm)}"),
        ("Fingerprint type", f"{fp_type} — {fp_type_meaning(fp_type)}"),
        ("Fingerprint", fingerprint),
    ]
    if truncated:
        rows.append(("Truncated", "yes"))
    return tuple(rows)


def _format_naptr(rdata: object) -> str:
    order = getattr(rdata, "order", "")
    preference = getattr(rdata, "preference", "")
    flags = _naptr_string(getattr(rdata, "flags", ""))
    service = _naptr_string(getattr(rdata, "service", ""))
    regexp = _naptr_string(getattr(rdata, "regexp", ""))
    replacement = _text(getattr(rdata, "replacement", "")) or "."
    return f'{order} {preference} "{flags}" "{service}" "{regexp}" {replacement}'


def _naptr_details(rdata: object) -> tuple[tuple[str, str], ...]:
    flags = _naptr_string(getattr(rdata, "flags", ""))
    replacement = _text(getattr(rdata, "replacement", "")) or "."
    return (
        ("Order", f"{getattr(rdata, 'order', '')} — lower number is tried first"),
        (
            "Preference",
            f"{getattr(rdata, 'preference', '')} — among the same order",
        ),
        ("Flags", f"{flags} — {flags_meaning(flags)}" if flags else flags_meaning(flags)),
        ("Services", _naptr_string(getattr(rdata, "service", ""))),
        ("Regexp", _naptr_string(getattr(rdata, "regexp", ""))),
        ("Replacement", replacement),
        (
            "Note",
            "Regexp is not executed; replacement is not followed (RFC 3403 listing only).",
        ),
    )


def _naptr_string(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _format_uri(rdata: object) -> str:
    priority = getattr(rdata, "priority", "")
    weight = getattr(rdata, "weight", "")
    target = _uri_target(getattr(rdata, "target", ""))
    return f'{priority} {weight} "{target}"'


def _uri_details(rdata: object) -> tuple[tuple[str, str], ...]:
    target = _uri_target(getattr(rdata, "target", ""))
    scheme = uri_scheme(target)
    return (
        ("Priority", f"{getattr(rdata, 'priority', '')} — lower number is tried first"),
        (
            "Weight",
            f"{getattr(rdata, 'weight', '')} — among the same priority",
        ),
        ("Target", target),
        ("Scheme", f"{scheme} — {scheme_meaning(scheme)}" if scheme else scheme_meaning(scheme)),
        (
            "Note",
            "URI is not fetched; the host inside it is not resolved (RFC 7553 listing only).",
        ),
    )


def _uri_target(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value).strip('"')


def _format_srv(rdata: object) -> str:
    priority = getattr(rdata, "priority", "")
    weight = getattr(rdata, "weight", "")
    port = getattr(rdata, "port", "")
    target = _text(getattr(rdata, "target", "")) or "."
    return f"{priority} {weight} {port} {target}"


def _srv_details(rdata: object) -> tuple[tuple[str, str], ...]:
    target = _text(getattr(rdata, "target", "")) or "."
    rows: list[tuple[str, str]] = [
        ("Priority", f"{getattr(rdata, 'priority', '')} — lower number is tried first"),
        ("Weight", f"{getattr(rdata, 'weight', '')} — among the same priority"),
        ("Port", str(getattr(rdata, "port", ""))),
        ("Target", target),
    ]
    if target == ".":
        rows.append(("Note", "Target '.' means this service is not offered (RFC 2782)."))
    return tuple(rows)


def _format_svcb(rdata: object) -> str:
    """Stable HTTPS/SVCB summary. ECH config is marked present, not dumped."""
    priority = getattr(rdata, "priority", "")
    target = _text(getattr(rdata, "target", "")) or "."
    extras: list[str] = []
    for key, value in _svcb_params(rdata):
        if key == "ech":
            extras.append("ech=(present)")
            continue
        extras.append(f"{key}={value}")
    if extras:
        return f"{priority} {target} " + " ".join(extras)
    return f"{priority} {target}".strip()


def _svcb_details(rdata: object) -> tuple[tuple[str, str], ...]:
    rows: list[tuple[str, str]] = []
    priority = getattr(rdata, "priority", None)
    if priority == 0:
        rows.append(
            (
                "Mode",
                "AliasMode — follow the target for HTTPS/SVCB parameters "
                "(this is a DNS record, not an HTTP redirect)",
            )
        )
    elif priority is not None:
        rows.append(
            (
                "Mode",
                "ServiceMode — this name advertises protocol parameters (RFC 9460)",
            )
        )
    for key, value in _svcb_params(rdata):
        if key == "ech":
            rows.append(
                (
                    "ECH",
                    "present — Encrypted Client Hello config in DNS, not a private key",
                )
            )
            continue
        if key == "alpn":
            rows.append(("ALPN", f"{value} — application protocols (e.g. HTTP/2, HTTP/3)"))
            continue
        if key == "port":
            rows.append(("Port", value))
            continue
        if key == "ipv4hint":
            rows.append(("IPv4 hint", value))
            continue
        if key == "ipv6hint":
            rows.append(("IPv6 hint", value))
            continue
        rows.append((key, value))
    return tuple(rows)


def _svcb_params(rdata: object) -> list[tuple[str, str]]:
    raw = getattr(rdata, "params", None) or {}
    items: list[tuple[str, str]] = []
    if not hasattr(raw, "items"):
        return items
    for key, value in raw.items():
        name = _svcb_key_name(key)
        if name == "ech":
            items.append((name, "present"))
            continue
        text = value.to_text() if hasattr(value, "to_text") else str(value)
        items.append((name, text.strip('"')))
    return items


def _svcb_key_name(key: object) -> str:
    try:
        from dns.rdtypes.svcbbase import key_to_text

        return str(key_to_text(key)).lower()
    except Exception:
        return str(key).lower()


def canonicalize_ip(value: str) -> str:
    """Normalize A/AAAA rdata (compress IPv6, keep dotted IPv4)."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def describe_ip_scope(value: str) -> str | None:
    """Return a non-global scope label, or None for typical public unicast.

    Missing AAAA or a private address is an observation, not a verdict.
    Documentation ranges (RFC 5737 / RFC 3849) are labeled separately so
    they are not scored as RFC1918-style misconfiguration.
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
    if _is_documentation(addr):
        return "documentation"
    if addr.is_private:
        return "private"
    if addr.is_reserved:
        return "reserved"
    return None


def _is_documentation(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(addr, ipaddress.IPv4Address):
        return any(
            addr in network
            for network in (
                ipaddress.ip_network("192.0.2.0/24"),
                ipaddress.ip_network("198.51.100.0/24"),
                ipaddress.ip_network("203.0.113.0/24"),
            )
        )
    return addr in ipaddress.ip_network("2001:db8::/32")


def _text(value: object) -> str:
    return str(value).rstrip(".")
