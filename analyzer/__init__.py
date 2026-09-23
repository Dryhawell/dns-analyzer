"""Core DNS analysis package."""

from analyzer.bimi import BimiObservation, evaluate_bimi
from analyzer.fcrdns import FcrdnsObservation, evaluate_fcrdns
from analyzer.mx import MxHostObservation, evaluate_mx_hosts
from analyzer.ns import NsHostObservation, evaluate_ns_hosts
from analyzer.cname import CnameTargetObservation, evaluate_cname_targets
from analyzer.soa import SoaNsObservation, evaluate_soa_ns
from analyzer.caa import CaaObservation, evaluate_caa
from analyzer.cds import CdsObservation, evaluate_cds
from analyzer.nsec import NsecObservation, evaluate_nsec
from analyzer.csync import CsyncObservation, evaluate_csync
from analyzer.zonemd import ZonemdObservation, evaluate_zonemd
from analyzer.rrsig import RrsigObservation, evaluate_rrsig
from analyzer.sshfp import SshfpObservation, evaluate_sshfp
from analyzer.tlsa import TlsaObservation, evaluate_tlsa
from analyzer.dmarc import DmarcObservation, evaluate_dmarc
from analyzer.dkim import DkimObservation, evaluate_dkim
from analyzer.dnssec import (
    DnssecDelegation,
    DnssecKey,
    DnssecObservation,
    evaluate_dnssec,
)
from analyzer.exceptions import (
    DNSQueryError,
    DNSNetworkError,
    DNSResolutionError,
    DNSTimeoutError,
    DomainNotFoundError,
    InvalidIPError,
    NoNameserversError,
)
from analyzer.models import CoreLookup, DNSRecord
from analyzer.resolver import DNSResolver
from analyzer.result import DNSAnalysisResult
from analyzer.reverse import looks_like_ip, ptr_name
from analyzer.risk import RiskScore, score_risk
from analyzer.security import SecurityAnalyzer, SecurityFinding, SecurityReport
from analyzer.spf import SpfObservation, inspect_spf
from analyzer.srv import SrvObservation, evaluate_srv
from analyzer.naptr import NaptrObservation, evaluate_naptr
from analyzer.uri import UriObservation, evaluate_uri
from analyzer.dname import DnameObservation, evaluate_dname
from analyzer.ipseckey import IpseckeyObservation, evaluate_ipseckey
from analyzer.cert import CertObservation, evaluate_cert
from analyzer.smimea import SmimeaObservation, evaluate_smimea
from analyzer.openpgpkey import OpenpgpkeyObservation, evaluate_openpgpkey
from analyzer.mtasts import MtaStsObservation, evaluate_mta_sts
from analyzer.tlsrpt import TlsRptObservation, evaluate_tls_rpt
from analyzer.validator import DomainValidationError, is_valid_domain, normalize_domain
from analyzer.version import __version__

__all__ = [
    "__version__",
    "DnssecObservation",
    "DnssecKey",
    "DnssecDelegation",
    "evaluate_dnssec",
    "CoreLookup",
    "DNSQueryError",
    "DNSNetworkError",
    "DNSRecord",
    "DNSAnalysisResult",
    "DNSResolutionError",
    "DNSResolver",
    "DNSTimeoutError",
    "DomainNotFoundError",
    "DomainValidationError",
    "InvalidIPError",
    "NoNameserversError",
    "SecurityAnalyzer",
    "SecurityFinding",
    "SecurityReport",
    "RiskScore",
    "score_risk",
    "is_valid_domain",
    "looks_like_ip",
    "normalize_domain",
    "SpfObservation",
    "DmarcObservation",
    "evaluate_dmarc",
    "DkimObservation",
    "evaluate_dkim",
    "SrvObservation",
    "evaluate_srv",
    "NaptrObservation",
    "evaluate_naptr",
    "UriObservation",
    "evaluate_uri",
    "DnameObservation",
    "evaluate_dname",
    "IpseckeyObservation",
    "evaluate_ipseckey",
    "CertObservation",
    "evaluate_cert",
    "SmimeaObservation",
    "evaluate_smimea",
    "OpenpgpkeyObservation",
    "evaluate_openpgpkey",
    "MtaStsObservation",
    "evaluate_mta_sts",
    "TlsRptObservation",
    "evaluate_tls_rpt",
    "BimiObservation",
    "evaluate_bimi",
    "TlsaObservation",
    "evaluate_tlsa",
    "SshfpObservation",
    "evaluate_sshfp",
    "FcrdnsObservation",
    "evaluate_fcrdns",
    "MxHostObservation",
    "evaluate_mx_hosts",
    "NsHostObservation",
    "evaluate_ns_hosts",
    "CnameTargetObservation",
    "evaluate_cname_targets",
    "SoaNsObservation",
    "evaluate_soa_ns",
    "CaaObservation",
    "evaluate_caa",
    "CdsObservation",
    "evaluate_cds",
    "NsecObservation",
    "evaluate_nsec",
    "CsyncObservation",
    "evaluate_csync",
    "ZonemdObservation",
    "evaluate_zonemd",
    "RrsigObservation",
    "evaluate_rrsig",
]
