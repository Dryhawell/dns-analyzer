"""SRV service discovery for a caller-supplied service name (RFC 2782).

SRV lives at _service._proto.<domain>, not at the apex. This module never
guesses services (sip, xmpp, minecraft, …). Missing a service you named
is an observation, not proof that nothing is published.

Default protocol is tcp. Use sip/udp for UDP. Target '.' means the service
is not offered at this name.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord

_SERVICE_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_PROTOCOLS = frozenset({"tcp", "udp"})
MAX_SRV = 8

SRV_NOTE = (
    "SRV maps a service name to a host and port (_service._proto.domain). "
    "This tool does not guess service names. A missing SRV is not a "
    "compromise. Priority is tried lowest first; weight balances hosts "
    "with the same priority. Target '.' means the service is not offered."
)


@dataclass(frozen=True)
class SrvSpec:
    service: str
    protocol: str

    @property
    def label(self) -> str:
        return f"{self.service}/{self.protocol}"


@dataclass(frozen=True)
class SrvObservation:
    status: str
    service: str
    protocol: str
    query_name: str
    records: tuple[DNSRecord, ...]
    note: str = SRV_NOTE
    error: str | None = None


class SrvSpecError(ValueError):
    """Raised when a --srv value cannot be used as a service name."""


def srv_query_name(domain: str, spec: SrvSpec) -> str:
    host = domain.rstrip(".").lower()
    return f"_{spec.service}._{spec.protocol}.{host}"


def normalize_srv_spec(raw: str) -> SrvSpec:
    if not isinstance(raw, str):
        raise SrvSpecError("SRV service must be a string.")
    value = raw.strip().strip(".").lower()
    if not value:
        raise SrvSpecError("SRV service cannot be empty.")
    protocol = "tcp"
    service = value
    if "/" in value:
        service, protocol = value.split("/", 1)
        service, protocol = service.strip(), protocol.strip()
    if protocol not in _PROTOCOLS:
        raise SrvSpecError(
            f"Invalid SRV protocol {protocol!r}. Use tcp or udp, for example sip or sip/udp."
        )
    if not service or not _SERVICE_LABEL.match(service):
        raise SrvSpecError(
            f"Invalid SRV service {raw!r}. Use a DNS label, for example sip or xmpp/tcp."
        )
    return SrvSpec(service=service, protocol=protocol)


def normalize_srv_specs(raw: Sequence[str]) -> tuple[SrvSpec, ...]:
    seen: list[SrvSpec] = []
    for item in raw:
        spec = normalize_srv_spec(item)
        if spec not in seen:
            seen.append(spec)
    if len(seen) > MAX_SRV:
        raise SrvSpecError(
            f"Too many --srv services (max {MAX_SRV}). "
            "This tool does not brute-force service names."
        )
    return tuple(seen)


def evaluate_srv(
    query_name: str,
    spec: SrvSpec,
    records: Sequence[DNSRecord],
    error: str | None = None,
) -> SrvObservation:
    rows = tuple(
        sorted(
            records,
            key=lambda item: (
                item.priority is None,
                item.priority if item.priority is not None else 0,
                item.value,
            ),
        )
    )
    if error:
        return SrvObservation(
            status="NOT DETECTED",
            service=spec.service,
            protocol=spec.protocol,
            query_name=query_name,
            records=(),
            error=error,
        )
    if not rows:
        return SrvObservation(
            status="NOT DETECTED",
            service=spec.service,
            protocol=spec.protocol,
            query_name=query_name,
            records=(),
        )
    return SrvObservation(
        status="FOUND",
        service=spec.service,
        protocol=spec.protocol,
        query_name=query_name,
        records=rows,
    )
