"""Core DNS analysis package."""

from analyzer.exceptions import (
    DNSQueryError,
    DNSResolutionError,
    DNSTimeoutError,
    DomainNotFoundError,
    InvalidIPError,
    NoNameserversError,
)
from analyzer.models import CoreLookup, DNSRecord
from analyzer.resolver import DNSResolver
from analyzer.reverse import looks_like_ip, ptr_name
from analyzer.validator import DomainValidationError, is_valid_domain, normalize_domain

__all__ = [
    "CoreLookup",
    "DNSQueryError",
    "DNSRecord",
    "DNSResolutionError",
    "DNSResolver",
    "DNSTimeoutError",
    "DomainNotFoundError",
    "DomainValidationError",
    "InvalidIPError",
    "NoNameserversError",
    "is_valid_domain",
    "looks_like_ip",
    "normalize_domain",
    "ptr_name",
]
