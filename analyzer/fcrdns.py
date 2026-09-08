"""Forward-confirmed reverse DNS (FCrDNS) for A/AAAA answers.

Forward DNS maps a name to an IP. Reverse DNS maps that IP to a name.
FCrDNS asks whether the PTR name's A/AAAA includes the original IP.

This is not a connection to the IP. Missing PTR is common. A mismatch
is not proof of hijacking (CDN, shared hosting, split-horizon).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

MAX_ADDRESSES = 8

FCRDNS_NOTE = (
    "FCrDNS checks whether each A/AAAA address has a PTR whose forward "
    "lookup returns the same IP. The IP is not contacted. Missing PTR is "
    "common. A mismatch is not proof of hijacking."
)


@dataclass(frozen=True)
class FcrdnsCheck:
    ip: str
    ptr_query: str
    ptr_names: tuple[str, ...]
    forward_ips: tuple[str, ...]
    status: str
    error: str | None = None


@dataclass(frozen=True)
class FcrdnsObservation:
    checks: tuple[FcrdnsCheck, ...]
    truncated: bool = False
    note: str = FCRDNS_NOTE


def evaluate_fcrdns(
    checks: Sequence[FcrdnsCheck],
    truncated: bool = False,
) -> FcrdnsObservation:
    return FcrdnsObservation(checks=tuple(checks), truncated=truncated)
