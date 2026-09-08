"""Core DNS analysis package."""

from analyzer.bimi import BimiObservation, evaluate_bimi
from analyzer.fcrdns import FcrdnsObservation, evaluate_fcrdns
from analyzer.sshfp import SshfpObservation, evaluate_sshfp
from analyzer.tlsa import TlsaObservation, evaluate_tlsa
from analyzer.dmarc import DmarcObservation, evaluate_dmarc
from analyzer.dkim import DkimObservation, evaluate_dkim
from analyzer.dnssec import DnssecObservation
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
from analyzer.mtasts import MtaStsObservation, evaluate_mta_sts
from analyzer.tlsrpt import TlsRptObservation, evaluate_tls_rpt
from analyzer.validator import DomainValidationError, is_valid_domain, normalize_domain
from analyzer.version import __version__

__all__ = [
    "__version__",
    "DnssecObservation",
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
]
