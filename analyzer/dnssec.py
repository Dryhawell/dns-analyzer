"""DNSSEC detection — observation only, not a verdict.

DNSSEC adds signatures (RRSIG) and keys (DNSKEY). The parent zone stores a
DS hash so a validating resolver can build a chain to the IANA root.

This module checks whether DNSKEY/DS are published and whether THIS
resolver set the AD (Authenticated Data) flag. It does not validate the
full chain against the root key.

NOT DETECTED does not mean the domain is compromised.
"""

from __future__ import annotations

from dataclasses import dataclass

DNSSEC_NOTE = (
    "DNSSEC authenticates DNS responses (integrity). "
    "NOT DETECTED does not mean the domain is compromised. "
    "This is not a full chain-of-trust validation against the IANA root key. "
    "Some recursive resolvers strip DNSKEY/DS or never set the AD flag, "
    "so a signed zone can still look undetected here."
)


@dataclass(frozen=True)
class DnssecObservation:
    status: str
    dnskey_found: bool
    ds_found: bool
    ad_flag: bool
    note: str = DNSSEC_NOTE
    error: str | None = None


def evaluate_dnssec(
    *,
    dnskey_found: bool,
    ds_found: bool,
    ad_flag: bool,
    error: str | None = None,
) -> DnssecObservation:
    """Map published records to DETECTED / NOT DETECTED.

    ENABLED in the product spec means 'signals present', not 'cryptographically
    proven by this tool'. We use DETECTED for that reason.
    """
    detected = dnskey_found or ds_found
    return DnssecObservation(
        status="DETECTED" if detected else "NOT DETECTED",
        dnskey_found=dnskey_found,
        ds_found=ds_found,
        ad_flag=ad_flag,
        error=error,
    )
