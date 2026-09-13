"""SOA primary vs NS set. Zone transfer is not attempted.

SOA mname names the primary master (RFC 1035). That name is often also in
the NS set, but a hidden primary (mname not published as NS) is a common
and valid design. This tool only compares DNS names. It does not open
TCP/53 to the primary and does not send AXFR.

Missing SOA is common on subdomains; the apex holds the SOA.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.models import DNSRecord
from analyzer.ns import ns_host_name, unique_ns_hosts

SOA_NS_NOTE = (
    "SOA mname names the primary master. ALIGNED means that name is also in "
    "the NS set. HIDDEN PRIMARY means it is not — a common, valid design. "
    "This tool does not contact the primary or attempt AXFR. Missing SOA is "
    "common on subdomains. None of these statuses is hijacking."
)


@dataclass(frozen=True)
class SoaNsObservation:
    status: str
    query_name: str
    mname: str | None
    serial: str | None
    ns_hosts: tuple[str, ...]
    note: str = SOA_NS_NOTE
    error: str | None = None


def soa_primary(record: DNSRecord) -> str | None:
    for label, value in record.details:
        if label == "Primary NS":
            host = ns_host_name(value)
            return host or None
    return None


def soa_serial(record: DNSRecord) -> str | None:
    for label, value in record.details:
        if label == "Serial":
            return value or None
    return None


def evaluate_soa_ns(
    query_name: str,
    mname: str | None,
    ns_hosts: Sequence[str] = (),
    serial: str | None = None,
    error: str | None = None,
) -> SoaNsObservation:
    hosts = tuple(ns_host_name(item) for item in ns_hosts if ns_host_name(item))
    if error and not mname:
        return SoaNsObservation(
            status="UNREADABLE",
            query_name=query_name,
            mname=None,
            serial=serial,
            ns_hosts=hosts,
            error=error,
        )
    if error and mname and not hosts:
        return SoaNsObservation(
            status="UNREADABLE",
            query_name=query_name,
            mname=mname,
            serial=serial,
            ns_hosts=(),
            error=error,
        )
    if not mname:
        return SoaNsObservation(
            status="NOT DETECTED",
            query_name=query_name,
            mname=None,
            serial=serial,
            ns_hosts=hosts,
            error=error,
        )
    if not hosts:
        return SoaNsObservation(
            status="NO NS",
            query_name=query_name,
            mname=mname,
            serial=serial,
            ns_hosts=(),
            error=error,
        )
    if mname in hosts:
        return SoaNsObservation(
            status="ALIGNED",
            query_name=query_name,
            mname=mname,
            serial=serial,
            ns_hosts=hosts,
            error=error,
        )
    return SoaNsObservation(
        status="HIDDEN PRIMARY",
        query_name=query_name,
        mname=mname,
        serial=serial,
        ns_hosts=hosts,
        error=error,
    )


def ns_names_from_records(records: Sequence[DNSRecord]) -> tuple[str, ...]:
    return unique_ns_hosts(records)
