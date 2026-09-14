"""URI listing for a caller-supplied name (RFC 7553).

URI publishes priority, weight, and a target URI. This tool only lists
those fields. It does not fetch the URI, does not resolve the host
inside it, and does not guess service prefixes such as _http._tcp.

Missing URI is common and is not a compromise. Default scans do not
query URI; pass --uri.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord

MAX_URI = 8

_VALUE_RE = re.compile(r'^(\d+)\s+(\d+)\s+"(.*)"\s*$')
_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
_SCHEME_MEANING = {
    "http": "HTTP URL in DNS; this tool does not fetch it",
    "https": "HTTPS URL in DNS; this tool does not fetch it",
    "ftp": "FTP URL in DNS; this tool does not connect",
    "sip": "SIP URI in DNS; this tool does not call it",
    "sips": "SIPS URI in DNS; this tool does not call it",
    "mailto": "mailto URI in DNS; this tool does not send mail",
}

URI_NOTE = (
    "URI (RFC 7553) lists a priority, weight, and target at this name. "
    "This tool does not fetch the URI, does not resolve the host inside it, "
    "and does not guess service prefixes such as _http._tcp. "
    "A missing URI is not a compromise. "
    "A published URL is text in DNS, not a page this tool retrieved."
)


@dataclass(frozen=True)
class UriTarget:
    priority: int
    weight: int
    target: str
    scheme: str
    scheme_meaning: str


@dataclass(frozen=True)
class UriObservation:
    status: str
    query_name: str
    uris: tuple[UriTarget, ...]
    truncated: bool = False
    note: str = URI_NOTE
    error: str | None = None


def uri_scheme(target: str) -> str:
    match = _SCHEME_RE.match(target.strip())
    if not match:
        return ""
    return match.group(1).lower()


def scheme_meaning(scheme: str) -> str:
    if not scheme:
        return "no scheme"
    return _SCHEME_MEANING.get(scheme, f"{scheme} URI in DNS; this tool does not follow it")


def target_from_record(record: DNSRecord) -> UriTarget | None:
    """Parse one URI row. The target is stored, never fetched."""
    match = _VALUE_RE.match(record.value)
    if match:
        priority = int(match.group(1))
        weight = int(match.group(2))
        target = match.group(3)
    else:
        parts = record.value.split(None, 2)
        if len(parts) < 3:
            return None
        try:
            priority = int(parts[0])
            weight = int(parts[1])
        except ValueError:
            return None
        target = parts[2].strip().strip('"')
    if not target:
        return None
    scheme = uri_scheme(target)
    return UriTarget(
        priority=priority,
        weight=weight,
        target=target,
        scheme=scheme,
        scheme_meaning=scheme_meaning(scheme),
    )


def evaluate_uri(
    query_name: str,
    records: Sequence[DNSRecord],
    error: str | None = None,
    limit: int = MAX_URI,
) -> UriObservation:
    """Map published URI records to FOUND / NOT DETECTED. No fetch."""
    parsed: list[UriTarget] = []
    for record in records:
        item = target_from_record(record)
        if item is None:
            continue
        parsed.append(item)
    parsed.sort(key=lambda item: (item.priority, item.weight, item.target))
    truncated = len(parsed) > limit
    uris = tuple(parsed[:limit])
    host = query_name.rstrip(".").lower()
    if not uris:
        return UriObservation(
            status="NOT DETECTED",
            query_name=host,
            uris=(),
            truncated=False,
            error=error,
        )
    return UriObservation(
        status="FOUND",
        query_name=host,
        uris=uris,
        truncated=truncated,
        error=error,
    )
