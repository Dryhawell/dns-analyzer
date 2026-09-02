"""SPF detection from TXT records (RFC 7208).

SPF answers: 'which hosts may send mail that claims to be from this domain?'
It is a signal against email spoofing, not a proof that mail is legitimate.
This phase does not follow include: chains and does not assign a risk score.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord

_SPF_PREFIX = re.compile(r"^v=spf1(?:\s|$)", re.IGNORECASE)

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
    "include: chains are not expanded in this phase."
)


@dataclass(frozen=True)
class SpfObservation:
    status: str
    policies: tuple[str, ...]
    all_term: str | None
    all_meaning: str | None
    multiple_records: bool
    note: str = SPF_NOTE
    error: str | None = None


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
    return SpfObservation(
        status="FOUND",
        policies=policies,
        all_term=all_term,
        all_meaning=all_meaning,
        multiple_records=len(policies) > 1,
    )


def _trailing_all(policy: str) -> tuple[str | None, str | None]:
    for part in reversed(policy.split()):
        token = part.lower()
        if token in _ALL_MEANING:
            return token, _ALL_MEANING[token]
    return None, None
