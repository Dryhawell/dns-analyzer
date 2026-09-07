"""SPF detection from TXT records (RFC 7208).

SPF answers: 'which hosts may send mail that claims to be from this domain?'
It is a signal against email spoofing, not a proof that mail is legitimate.

include: and redirect= are looked up one hop (max 10 names). Nested include:,
a, mx, ptr, and exists are not evaluated. This is not a full SPF check.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace

from analyzer.models import DNSRecord

_SPF_PREFIX = re.compile(r"^v=spf1(?:\s|$)", re.IGNORECASE)
_INCLUDE = re.compile(r"(?:^|\s)[+\-~?]?include:([^\s]+)", re.IGNORECASE)
_REDIRECT = re.compile(r"(?:^|\s)redirect=([^\s]+)", re.IGNORECASE)
_SPF_NAME_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
MAX_SPF_LOOKUPS = 10

_ALL_MEANING = {
    "-all": "fail — receivers should reject mail from other hosts",
    "~all": "softfail — often accepted but marked as suspicious",
    "?all": "neutral — no recommendation",
    "+all": "pass — any host may send (unusual)",
    "all": "pass — bare 'all' means +all (unusual)",
}

SPF_NOTE = (
    "SPF lists servers allowed to send mail for this domain. "
    "NOT DETECTED does not mean the domain is compromised. "
    "include: and redirect= are followed one hop (max 10 lookups). "
    "Nested include: and a/mx/ptr/exists are not evaluated. "
    "This is not a full RFC 7208 check."
)

TxtFetch = Callable[[str], tuple[Sequence[DNSRecord], str | None]]


@dataclass(frozen=True)
class SpfHop:
    """One include: or redirect= target, looked up once."""

    kind: str
    domain: str
    status: str
    policy: str | None
    all_term: str | None
    all_meaning: str | None
    nested_includes: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True)
class SpfObservation:
    status: str
    policies: tuple[str, ...]
    all_term: str | None
    all_meaning: str | None
    multiple_records: bool
    note: str = SPF_NOTE
    error: str | None = None
    hops: tuple[SpfHop, ...] = ()


def inspect_spf(
    txt_records: Sequence[DNSRecord],
    errors: Sequence[tuple[str, str]] = (),
) -> SpfObservation:
    """Find v=spf1 policies in already-fetched TXT records."""
    txt_error = next((message for label, message in errors if label == "TXT"), None)
    policies = tuple(
        record.value.strip()
        for record in txt_records
        if _SPF_PREFIX.search(record.value.strip())
    )

    if not policies:
        error = None
        if txt_error:
            error = f"TXT query failed ({txt_error}); SPF could not be read."
        return SpfObservation(
            status="NOT DETECTED",
            policies=(),
            all_term=None,
            all_meaning=None,
            multiple_records=False,
            error=error,
        )

    all_term, all_meaning = _trailing_all(policies[0])
    for policy in policies[1:]:
        term, meaning = _trailing_all(policy)
        if term in {"+all", "all"}:
            all_term, all_meaning = term, meaning
            break
    return SpfObservation(
        status="FOUND",
        policies=policies,
        all_term=all_term,
        all_meaning=all_meaning,
        multiple_records=len(policies) > 1,
    )


def include_domains(policy: str) -> tuple[str, ...]:
    """include: names in order, first occurrence only."""
    seen: list[str] = []
    for match in _INCLUDE.finditer(policy):
        name = _spf_lookup_name(match.group(1))
        if name and name not in seen:
            seen.append(name)
    return tuple(seen)


def redirect_domain(policy: str) -> str | None:
    match = _REDIRECT.search(policy)
    if match is None:
        return None
    return _spf_lookup_name(match.group(1))


def expand_spf(observation: SpfObservation, fetch_txt: TxtFetch) -> SpfObservation:
    """Resolve include:/redirect= one hop. Does not evaluate mechanisms."""
    if observation.status != "FOUND" or not observation.policies:
        return observation
    policy = observation.policies[0]
    targets: list[tuple[str, str]] = [
        ("include", name) for name in include_domains(policy)
    ]
    redirected = redirect_domain(policy)
    if redirected is not None:
        targets.append(("redirect", redirected))
    if not targets:
        return observation

    hops: list[SpfHop] = []
    seen: set[str] = set()
    for kind, domain in targets:
        if domain in seen:
            continue
        if len(seen) >= MAX_SPF_LOOKUPS:
            hops.append(
                SpfHop(
                    kind=kind,
                    domain=domain,
                    status="NOT DETECTED",
                    policy=None,
                    all_term=None,
                    all_meaning=None,
                    error=f"SPF lookup cap ({MAX_SPF_LOOKUPS}) reached; not queried.",
                )
            )
            continue
        seen.add(domain)
        hops.append(_lookup_hop(kind, domain, fetch_txt))
    return replace(observation, hops=tuple(hops))


def _lookup_hop(kind: str, domain: str, fetch_txt: TxtFetch) -> SpfHop:
    records, error = fetch_txt(domain)
    nested = inspect_spf(records)
    if error:
        return SpfHop(
            kind=kind,
            domain=domain,
            status="NOT DETECTED",
            policy=None,
            all_term=None,
            all_meaning=None,
            error=error,
        )
    if nested.status != "FOUND" or not nested.policies:
        return SpfHop(
            kind=kind,
            domain=domain,
            status="NOT DETECTED",
            policy=None,
            all_term=None,
            all_meaning=None,
            nested_includes=include_domains(nested.policies[0]) if nested.policies else (),
        )
    nested_names = include_domains(nested.policies[0])
    return SpfHop(
        kind=kind,
        domain=domain,
        status="FOUND",
        policy=nested.policies[0],
        all_term=nested.all_term,
        all_meaning=nested.all_meaning,
        nested_includes=nested_names,
    )


def _spf_lookup_name(raw: str) -> str | None:
    """Accept underscore labels (_spf.google.com). Reject macros and junk."""
    value = raw.strip().strip(".").lower()
    if not value or "%{" in value or len(value) > 253:
        return None
    labels = value.split(".")
    if len(labels) < 2:
        return None
    if any(not label or len(label) > 63 or not _SPF_NAME_LABEL.match(label) for label in labels):
        return None
    return value


def _trailing_all(policy: str) -> tuple[str | None, str | None]:
    for part in reversed(policy.split()):
        token = part.lower()
        if token in _ALL_MEANING:
            return token, _ALL_MEANING[token]
    return None, None
