"""CAA property summary (RFC 8659). CAs and CT logs are not contacted.

CAA says which certificate authorities may issue certificates for a name.
`issue` covers this name, `issuewild` covers wildcards, and `iodef` is
where a CA may send a policy-violation report. This tool only reads the
DNS records. It does not talk to CAs or check Certificate Transparency.

NOT DETECTED is common. CAs may walk to a parent name. Absence is not a
compromise. A value of `;` means no CA is authorized for that property.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord

MAX_CAA_ITEMS = 8
ISSUER_CRITICAL_FLAG = 128

_TAG_MEANING = {
    "issue": "CA authorized to issue certificates for this name",
    "issuewild": "CA authorized to issue wildcard certificates",
    "iodef": "incident report URI",
}

_VALUE_RE = re.compile(r'^(\d+)\s+(\S+)\s+"(.*)"\s*$')

CAA_NOTE = (
    "CAA (RFC 8659) lists which CAs may issue certificates for this name. "
    "issue, issuewild, and iodef are DNS properties, not a CA or CT check. "
    "This tool does not talk to CAs or fetch report URIs. "
    "NOT DETECTED is common; CAs may walk to a parent name. "
    "Absence is not a compromise. "
    "A value of ';' means no CA is authorized for that property."
)


@dataclass(frozen=True)
class CaaProperty:
    flags: int
    issuer_critical: bool
    tag: str
    tag_meaning: str
    value: str


@dataclass(frozen=True)
class CaaObservation:
    status: str
    query_name: str
    properties: tuple[CaaProperty, ...]
    issue: tuple[str, ...]
    issuewild: tuple[str, ...]
    iodef: tuple[str, ...]
    truncated: bool = False
    note: str = CAA_NOTE
    error: str | None = None


def tag_meaning(tag: str) -> str:
    return _TAG_MEANING.get(tag.lower(), "unknown CAA property")


def property_from_record(record: DNSRecord) -> CaaProperty | None:
    """Parse one CAA row. Public policy text only; no CA lookup."""
    match = _VALUE_RE.match(record.value)
    if match:
        flags = int(match.group(1))
        tag = match.group(2)
        value = match.group(3)
    else:
        parts = record.value.split(None, 2)
        if len(parts) < 2:
            return None
        try:
            flags = int(parts[0])
        except ValueError:
            return None
        tag = parts[1]
        value = parts[2].strip().strip('"') if len(parts) > 2 else ""
    tag = tag.lower()
    return CaaProperty(
        flags=flags,
        issuer_critical=bool(flags & ISSUER_CRITICAL_FLAG),
        tag=tag,
        tag_meaning=tag_meaning(tag),
        value=value,
    )


def evaluate_caa(
    query_name: str,
    records: Sequence[DNSRecord],
    error: str | None = None,
    limit: int = MAX_CAA_ITEMS,
) -> CaaObservation:
    """Map published CAA records to FOUND / NOT DETECTED / UNREADABLE."""
    parsed: list[CaaProperty] = []
    truncated = False
    for record in records:
        item = property_from_record(record)
        if item is None:
            continue
        if len(parsed) >= limit:
            truncated = True
            break
        parsed.append(item)
    properties = tuple(parsed)
    issue = tuple(item.value for item in properties if item.tag == "issue")
    issuewild = tuple(item.value for item in properties if item.tag == "issuewild")
    iodef = tuple(item.value for item in properties if item.tag == "iodef")
    if not properties:
        status = "UNREADABLE" if error else "NOT DETECTED"
        return CaaObservation(
            status=status,
            query_name=query_name,
            properties=(),
            issue=(),
            issuewild=(),
            iodef=(),
            truncated=False,
            error=error,
        )
    return CaaObservation(
        status="FOUND",
        query_name=query_name,
        properties=properties,
        issue=issue,
        issuewild=issuewild,
        iodef=iodef,
        truncated=truncated,
        error=error,
    )
