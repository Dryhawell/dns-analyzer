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
import dns.flags
import dns.resolver

from analyzer.dmarc import DmarcObservation, dmarc_query_name, evaluate_dmarc
from analyzer.dnssec import DnssecObservation, evaluate_dnssec

from analyzer.exceptions import (
    DNSNetworkError,
    DNSQueryError,
    DNSResolutionError,
    DNSTimeoutError,
    DomainNotFoundError,
    NoNameserversError,
)
from analyzer.models import CoreLookup, DNSRecord
from analyzer.records import records_from_answer
from analyzer.reverse import ptr_name
from utils.logger import get_logger

_DEFAULT_TIMEOUT = 5.0
_log = get_logger("resolver")


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
        """Query core record types. A NXDOMAIN/timeout still aborts.

        Later types (AAAA, CNAME, MX, ...) collect errors instead of
        discarding the whole result — CAA timeouts are common on some resolvers.
        """
        errors: list[tuple[str, str]] = []

        def collect(label: str, query) -> tuple[DNSRecord, ...]:
            try:
                return tuple(query())
            except DomainNotFoundError:
                if label == "A":
                    raise
                errors.append((label, "Domain does not exist."))
                return ()
            except DNSQueryError as exc:
                if label == "A":
                    raise
                errors.append((label, str(exc)))
                return ()

        return CoreLookup(
            a=collect("A", lambda: self.resolve_a(name)),
            aaaa=collect("AAAA", lambda: self.resolve_aaaa(name)),
            cname=collect("CNAME", lambda: self.resolve_cname(name)),
            mx=collect("MX", lambda: self.resolve_mx(name)),
            ns=collect("NS", lambda: self.resolve_ns(name)),
            txt=collect("TXT", lambda: self.resolve_txt(name)),
            soa=collect("SOA", lambda: self.resolve_soa(name)),
            caa=collect("CAA", lambda: self.resolve_caa(name)),
            errors=tuple(errors),
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
        """Query a PTR name such as 4.4.8.8.in-addr.arpa."""
        return self._query(name, "PTR")

    def resolve_reverse(self, ip: str) -> list[DNSRecord]:
        """IP → hostname. NXDOMAIN means no PTR, not a fatal error."""
        qname = ptr_name(ip)
        try:
            return self.resolve_ptr(qname)
        except DomainNotFoundError:
            return []

    def inspect_dmarc(self, name: str) -> DmarcObservation:
        """TXT lookup at _dmarc.<name>. NXDOMAIN means not published."""
        qname = dmarc_query_name(name)
        try:
            records = self.resolve_txt(qname)
        except DomainNotFoundError:
            return evaluate_dmarc(qname, ())
        except DNSQueryError as exc:
            return evaluate_dmarc(qname, (), error=str(exc))
        return evaluate_dmarc(qname, records)

    def inspect_dnssec(self, name: str) -> DnssecObservation:
        """Look for DNSKEY/DS and the AD flag. Failures become observations."""
        client = dns.resolver.Resolver(configure=True)
        client.timeout = self.timeout
        client.lifetime = self.timeout
        if self._client.nameservers:
            client.nameservers = list(self._client.nameservers)
        # DO bit: ask the resolver to include DNSSEC records when it can.
        client.use_edns(0, dns.flags.DO, 1232)

        errors: list[str] = []
        dnskey_found, ad_key = self._dnssec_probe(client, name, "DNSKEY", errors)
        ds_found, ad_ds = self._dnssec_probe(client, name, "DS", errors)
        return evaluate_dnssec(
            dnskey_found=dnskey_found,
            ds_found=ds_found,
            ad_flag=ad_key or ad_ds,
            error="; ".join(errors) if errors else None,
        )

    def _dnssec_probe(
        self,
        client: dns.resolver.Resolver,
        name: str,
        rdtype: str,
        errors: list[str],
    ) -> tuple[bool, bool]:
        _log.info("Querying %s record for %s", rdtype, name)
        try:
            answer = client.resolve(name, rdtype, search=False)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False, False
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            _log.warning("DNS query timeout for %s %s", rdtype, name)
            errors.append(f"{rdtype} query timed out")
            return False, False
        except dns.resolver.NoNameservers:
            _log.warning("No nameservers for %s %s", rdtype, name)
            errors.append(f"{rdtype} query had no nameservers")
            return False, False
        except OSError:
            _log.warning("Network error for %s %s", rdtype, name)
            errors.append(f"{rdtype} query had a network error")
            return False, False
        except dns.exception.DNSException:
            _log.warning("DNS query failed for %s %s", rdtype, name)
            errors.append(f"{rdtype} query failed")
            return False, False

        response = getattr(answer, "response", None)
        ad_flag = bool(response is not None and (response.flags & dns.flags.AD))
        return True, ad_flag

    def _query(self, name: str, record_type: str) -> list[DNSRecord]:
        """Ask the recursive resolver for one record type.

        search=False prevents Windows/Linux search suffixes from turning
        example.com into example.com.company.local.
        """
        _log.info("Querying %s record for %s", record_type, name)
        try:
            answer = self._client.resolve(name, record_type, search=False)
        except dns.resolver.NXDOMAIN as exc:
            _log.info("NXDOMAIN for %s %s", record_type, name)
            raise DomainNotFoundError() from exc
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NoNameservers as exc:
            _log.warning("No nameservers for %s %s", record_type, name)
            raise NoNameserversError() from exc
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout) as exc:
            _log.warning("DNS query timeout for %s %s", record_type, name)
            raise DNSTimeoutError() from exc
        except OSError as exc:
            _log.warning("Network error for %s %s", record_type, name)
            raise DNSNetworkError() from exc
        except dns.exception.DNSException as exc:
            _log.warning("DNS query failed for %s %s", record_type, name)
            raise DNSResolutionError() from exc

        try:
            records = records_from_answer(record_type, name, answer)
        except (TypeError, ValueError, AttributeError) as exc:
            _log.warning("Could not parse %s answer for %s", record_type, name)
            raise DNSResolutionError() from exc
        _log.info("Received %s %s record(s) for %s", len(records), record_type, name)
        return records
