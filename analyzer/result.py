"""Aggregate result of one analysis run.

Kept out of models.py so DNSRecord stays free of security imports
(security.py already imports CoreLookup).
"""

from __future__ import annotations

from dataclasses import dataclass

from analyzer.bimi import BimiObservation
from analyzer.compare import ResolverComparison
from analyzer.dmarc import DmarcObservation
from analyzer.dkim import DkimObservation
from analyzer.dnssec import DnssecObservation
from analyzer.models import DNSRecord
from analyzer.mtasts import MtaStsObservation
from analyzer.security import SecurityReport
from analyzer.spf import SpfObservation
from analyzer.srv import SrvObservation
from analyzer.naptr import NaptrObservation
from analyzer.uri import UriObservation
from analyzer.dname import DnameObservation
from analyzer.ipseckey import IpseckeyObservation
from analyzer.fcrdns import FcrdnsObservation
from analyzer.mx import MxHostObservation
from analyzer.ns import NsHostObservation
from analyzer.cname import CnameTargetObservation
from analyzer.soa import SoaNsObservation
from analyzer.caa import CaaObservation
from analyzer.cds import CdsObservation
from analyzer.nsec import NsecObservation
from analyzer.csync import CsyncObservation
from analyzer.zonemd import ZonemdObservation
from analyzer.rrsig import RrsigObservation
from analyzer.sshfp import SshfpObservation
from analyzer.tlsa import TlsaObservation
from analyzer.tlsrpt import TlsRptObservation


@dataclass(frozen=True)
class DNSAnalysisResult:
    """One completed lookup, ready for CLI display or file export."""

    target: str
    mode: str
    scan_time: str
    duration_ms: int
    records: tuple[DNSRecord, ...]
    errors: tuple[tuple[str, str], ...] = ()
    dnssec: DnssecObservation | None = None
    spf: SpfObservation | None = None
    dmarc: DmarcObservation | None = None
    mta_sts: MtaStsObservation | None = None
    tls_rpt: TlsRptObservation | None = None
    bimi: BimiObservation | None = None
    tlsa: TlsaObservation | None = None
    sshfp: SshfpObservation | None = None
    fcrdns: FcrdnsObservation | None = None
    mx_hosts: MxHostObservation | None = None
    ns_hosts: NsHostObservation | None = None
    cname_targets: CnameTargetObservation | None = None
    soa_ns: SoaNsObservation | None = None
    caa: CaaObservation | None = None
    cds: CdsObservation | None = None
    nsec: NsecObservation | None = None
    csync: CsyncObservation | None = None
    zonemd: ZonemdObservation | None = None
    rrsig: RrsigObservation | None = None
    dkim: tuple[DkimObservation, ...] | None = None
    srv: tuple[SrvObservation, ...] | None = None
    naptr: NaptrObservation | None = None
    uri: UriObservation | None = None
    dname: DnameObservation | None = None
    ipseckey: IpseckeyObservation | None = None
    security: SecurityReport | None = None
    ptr_query: str | None = None
    view_record_types: tuple[str, ...] | None = None
    view_security: bool = True
    comparison: ResolverComparison | None = None
