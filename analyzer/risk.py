"""Local risk heuristic — not CVSS, not a standard, not a compromise grade.

Higher numbers mean more concern *in this tool*, not a probability of breach.
DNSSEC absence is scored lightly because many resolvers hide those records.
Lookup failures (timeouts) are not scored as missing policy.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol


class _ScoredFinding(Protocol):
    code: str
    title: str

SCORE_NOTE = (
    "This score is a local heuristic, not CVSS, not a security standard, "
    "and not a grade of compromise. Contributions are listed so you can "
    "see exactly what was counted. DNSSEC absence is not heavily penalized."
)

# Points added per finding code. Missing DNSSEC stays small on purpose.
WEIGHTS: dict[str, int] = {
    "dnssec_not_detected": 5,
    "spf_unreadable": 0,
    "spf_missing": 8,
    "spf_multiple": 16,
    "spf_plus_all": 22,
    "spf_include_unreadable": 0,
    "spf_include_missing": 8,
    "dmarc_unreadable": 0,
    "dmarc_missing": 10,
    "dmarc_multiple": 16,
    "dmarc_p_none": 5,
    "caa_missing": 2,
    "dkim_unreadable": 0,
    "dkim_selector_missing": 0,
    "dkim_revoked": 8,
    "dkim_multiple": 5,
    "srv_unreadable": 0,
    "srv_missing": 0,
    "mtasts_unreadable": 0,
    "mtasts_missing": 0,
    "mtasts_multiple": 5,
    "mtasts_id_missing": 0,
    "tlsrpt_unreadable": 0,
    "tlsrpt_missing": 0,
    "tlsrpt_multiple": 5,
    "tlsrpt_rua_missing": 0,
    "bimi_unreadable": 0,
    "bimi_missing": 0,
    "bimi_multiple": 5,
    "bimi_location_missing": 0,
    "bimi_without_enforcing_dmarc": 0,
    "tlsa_unreadable": 0,
    "tlsa_missing": 0,
    "sshfp_unreadable": 0,
    "sshfp_missing": 0,
    "fcrdns_unreadable": 0,
    "fcrdns_no_ptr": 0,
    "fcrdns_mismatch": 0,
    "address_non_global": 22,
    "cname_dangling": 8,
    "txt_many": 1,
}

_MAX = 100


@dataclass(frozen=True)
class ScoreContribution:
    code: str
    label: str
    points: int


@dataclass(frozen=True)
class RiskScore:
    value: int
    band: str
    contributions: tuple[ScoreContribution, ...]
    raw_total: int
    note: str = SCORE_NOTE

    @property
    def capped(self) -> bool:
        return self.raw_total > _MAX


def band_for(value: int) -> str:
    """Map 0–100 onto the project bands (higher = more concern)."""
    if value <= 20:
        return "LOW"
    if value <= 50:
        return "MEDIUM"
    if value <= 75:
        return "HIGH"
    return "CRITICAL"


def score_risk(findings: Sequence[_ScoredFinding]) -> RiskScore:
    """Sum transparent weights from findings, then cap at 100."""
    contributions: list[ScoreContribution] = []
    raw = 0
    for finding in findings:
        points = WEIGHTS.get(finding.code, 0)
        if points <= 0:
            continue
        contributions.append(
            ScoreContribution(code=finding.code, label=finding.title, points=points)
        )
        raw += points
    value = min(raw, _MAX)
    return RiskScore(
        value=value,
        band=band_for(value),
        contributions=tuple(contributions),
        raw_total=raw,
    )
