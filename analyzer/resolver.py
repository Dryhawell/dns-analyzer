"""Central DNS resolver wrapper around dnspython.

dnspython does not "look up a website". It builds a DNS query message
(RFC 1035), sends it to a recursive resolver over UDP/53 (TCP if the
answer is truncated), and parses the binary response into Python objects.

By default we use the operating system's resolver list (the same path
nslookup uses). Nameserver IPs are not hard-coded; later phases can pass
a config-driven list into DNSResolver(nameservers=...).
"""

from __future__ import annotations

from collections.abc import Sequence

import dns.exception
import dns.resolver

from analyzer.exceptions import (
    DNSResolutionError,
    DNSTimeoutError,
    DomainNotFoundError,
    NoNameserversError,
)
from analyzer.models import CoreLookup, DNSRecord
from analyzer.records import records_from_answer

_DEFAULT_TIMEOUT = 5.0


class DNSResolver:
    """Query DNS record types and return DNSRecord dataclasses."""

    def __init__(
        self,
        timeout: float = _DEFAULT_TIMEOUT,
        nameservers: Sequence[str] | None = None,
    ) -> None:
        self.timeout = timeout
        self._client = dns.resolver.Resolver(configure=True)
        # timeout = wait per nameserver; lifetime = budget for the whole query
        self._client.timeout = timeout
        self._client.lifetime = timeout
        if nameservers:
            self._client.nameservers = list(nameservers)

    def resolve_a(self, name: str) -> list[DNSRecord]:
        return self._query(name, "A")

    def resolve_aaaa(self, name: str) -> list[DNSRecord]:
        return self._query(name, "AAAA")

    def resolve_addresses(self, name: str) -> tuple[list[DNSRecord], list[DNSRecord]]:
        """Query A then AAAA. NXDOMAIN on A stops the pair (name does not exist)."""
        return self.resolve_a(name), self.resolve_aaaa(name)

    def lookup_core(self, name: str) -> CoreLookup:
        """A / AAAA / CNAME / MX / NS for one hostname."""
        ipv4, ipv6 = self.resolve_addresses(name)
        return CoreLookup(
            a=tuple(ipv4),
            aaaa=tuple(ipv6),
            cname=tuple(self.resolve_cname(name)),
            mx=tuple(self.resolve_mx(name)),
            ns=tuple(self.resolve_ns(name)),
        )

    def resolve_cname(self, name: str) -> list[DNSRecord]:
        return self._query(name, "CNAME")

    def resolve_mx(self, name: str) -> list[DNSRecord]:
        return self._query(name, "MX")

    def resolve_ns(self, name: str) -> list[DNSRecord]:
        return self._query(name, "NS")

    def resolve_txt(self, name: str) -> list[DNSRecord]:
        return self._query(name, "TXT")

    def resolve_soa(self, name: str) -> list[DNSRecord]:
        return self._query(name, "SOA")

    def resolve_caa(self, name: str) -> list[DNSRecord]:
        return self._query(name, "CAA")

    def resolve_ptr(self, name: str) -> list[DNSRecord]:
        """Query a PTR name such as 4.4.8.8.in-addr.arpa (Phase 7 wraps IPs)."""
        return self._query(name, "PTR")

    def _query(self, name: str, record_type: str) -> list[DNSRecord]:
        """Ask the recursive resolver for one record type.

        search=False prevents Windows/Linux search suffixes from turning
        example.com into example.com.company.local.
        """
        try:
            answer = self._client.resolve(name, record_type, search=False)
        except dns.resolver.NXDOMAIN as exc:
            raise DomainNotFoundError() from exc
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NoNameservers as exc:
            raise NoNameserversError() from exc
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout) as exc:
            raise DNSTimeoutError() from exc
        except dns.exception.DNSException as exc:
            raise DNSResolutionError() from exc

        return records_from_answer(record_type, name, answer)
