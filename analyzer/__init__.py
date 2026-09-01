"""Core DNS analysis package."""

from analyzer.validator import DomainValidationError, is_valid_domain, normalize_domain

__all__ = [
    "DomainValidationError",
    "is_valid_domain",
    "normalize_domain",
]
