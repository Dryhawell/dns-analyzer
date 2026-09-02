"""Core DNS analysis package."""

from analyzer.exceptions import (
    DNSQueryError,
    DNSResolutionError,
    DNSTimeoutError,
    DomainNotFoundError,
    NoNameserversError,
)
from analyzer.models import CoreLookup, DNSRecord
from analyzer.resolver import DNSResolver
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
    "NoNameserversError",
    "is_valid_domain",
    "normalize_domain",
]
