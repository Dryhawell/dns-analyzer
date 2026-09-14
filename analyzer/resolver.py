"""Central DNS resolver wrapper around dnspython.

dnspython does not "look up a website". It builds a DNS query message
(RFC 1035), sends it to a recursive resolver over UDP/53 (TCP if the
answer is truncated), and parses the binary response into Python objects.

By default we use the operating system's resolver list (the same path
nslookup uses). Nameserver IPs are not hard-coded; pass them via
DNSResolver(nameservers=...) or a JSON config file (Phase 20).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

import dns.exception
import dns.flags
import dns.resolver

from analyzer.bimi import (
    DEFAULT_SELECTOR,
    BimiObservation,
    bimi_query_name,
    evaluate_bimi,
)
from analyzer.fcrdns import (
    MAX_ADDRESSES,
    FcrdnsCheck,
    FcrdnsObservation,
    evaluate_fcrdns,
)
from analyzer.mx import (
    MAX_HOSTS,
    MxHostCheck,
    MxHostObservation,
    evaluate_mx_hosts,
    mx_host_name,
    unique_mx_hosts,
)
from analyzer.ns import (
    MAX_HOSTS as MAX_NS_HOSTS,
    NsHostCheck,
    NsHostObservation,
    evaluate_ns_hosts,
    ns_in_bailiwick,
    unique_ns_hosts,
)
from analyzer.cname import (
    MAX_HOPS,
    MAX_TARGETS,
    CnameTargetCheck,
    CnameTargetObservation,
    cname_target_name,
    evaluate_cname_targets,
    unique_cname_targets,
)
from analyzer.soa import (
    SoaNsObservation,
    evaluate_soa_ns,
    ns_names_from_records,
    soa_primary,
    soa_serial,
)
from analyzer.caa import CaaObservation, evaluate_caa
from analyzer.dmarc import DmarcObservation, dmarc_query_name, evaluate_dmarc
from analyzer.dkim import DkimObservation, dkim_query_name, evaluate_dkim
from analyzer.dnssec import (
    MAX_DNSSEC_ITEMS,
    DnssecObservation,
    evaluate_dnssec,
    parse_delegations,
    parse_dnskeys,
)
from analyzer.mtasts import MtaStsObservation, evaluate_mta_sts, mta_sts_policy_host, mta_sts_query_name
from analyzer.spf import SpfObservation, expand_spf as apply_spf_hops
from analyzer.srv import SrvObservation, SrvSpec, evaluate_srv, srv_query_name
from analyzer.sshfp import SshfpObservation, evaluate_sshfp
from analyzer.tlsa import TlsaObservation, evaluate_tlsa, tlsa_query_name
from analyzer.tlsrpt import TlsRptObservation, evaluate_tls_rpt, tls_rpt_query_name

from analyzer.exceptions import (
    DNSNetworkError,
    DNSQueryError,
    DNSResolutionError,
    DNSTimeoutError,
    DomainNotFoundError,
    NoNameserversError,
)
from analyzer.models import CoreLookup, DNSRecord
from analyzer.records import canonicalize_ip, records_from_answer
from analyzer.reverse import ptr_name
from utils.logger import get_logger

_DEFAULT_TIMEOUT = 5.0
CORE_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "HTTPS", "SVCB")
_log = get_logger("resolver")


def _unique_ips(lookup: CoreLookup) -> tuple[str, ...]:
    seen: list[str] = []
    for record in lookup.a + lookup.aaaa:
        value = canonicalize_ip(record.value)
        if value not in seen:
            seen.append(value)
    return tuple(seen)


def _normalize_types(types: Sequence[str] | None) -> tuple[str, ...]:
    """Restrict a lookup to known core types. A is always included.

    A answers "does this name exist?" NXDOMAIN there still aborts the scan.
    An empty list therefore means A only, not "query nothing".
    """
    if types is None:
        return CORE_TYPES
    wanted: set[str] = {"A"}
    for raw in types:
        label = str(raw).strip().upper()
        if label not in CORE_TYPES:
            raise ValueError(f"Unsupported core record type: {raw!r}")
        wanted.add(label)
    return tuple(label for label in CORE_TYPES if label in wanted)


class DNSResolver:
    """Query DNS record types and return DNSRecord dataclasses."""

    def __init__(
        self,
        timeout: float = _DEFAULT_TIMEOUT,
        nameservers: Sequence[str] | None = None,
    ) -> None:
        self.timeout = timeout
        self._client = dns.resolver.Resolver(configure=True)
        if nameservers:
            self._client.nameservers = list(nameservers)
        self._apply_timeouts()
        self._lock = Lock()
        self.parallel = True

    def resolve_a(self, name: str) -> list[DNSRecord]:
        return self._query(name, "A")

    def resolve_aaaa(self, name: str) -> list[DNSRecord]:
        return self._query(name, "AAAA")

    def resolve_addresses(self, name: str) -> tuple[list[DNSRecord], list[DNSRecord]]:
        """Query A then AAAA. NXDOMAIN on A stops the pair (name does not exist)."""
        return self.resolve_a(name), self.resolve_aaaa(name)

    def lookup_core(
        self,
        name: str,
        types: Sequence[str] | None = None,
    ) -> CoreLookup:
        """Query selected core types. A NXDOMAIN/timeout still aborts.

        A is queried first (does this name exist?). Remaining types run in
        parallel when there are two or more — they are independent questions.
        Later-type failures are collected so a CAA timeout does not drop A.
        """
        wanted = _normalize_types(types)
        buckets: dict[str, tuple[DNSRecord, ...]] = {label: () for label in CORE_TYPES}
        errors: list[tuple[str, str]] = []

        if "A" in wanted:
            records, error = self._try_type(name, "A", fatal=True)
            buckets["A"] = records
            if error:
                errors.append(error)

        rest = [label for label in wanted if label != "A"]
        if len(rest) >= 2 and self.parallel:
            _log.info("Querying %s remaining types in parallel for %s", len(rest), name)
            with ThreadPoolExecutor(max_workers=min(8, len(rest))) as pool:
                futures = [pool.submit(self._try_type, name, label, False) for label in rest]
                for label, future in zip(rest, futures, strict=True):
                    records, error = future.result()
                    buckets[label] = records
                    if error:
                        errors.append(error)
        else:
            for label in rest:
                records, error = self._try_type(name, label, fatal=False)
                buckets[label] = records
                if error:
                    errors.append(error)

        return CoreLookup(
            a=buckets["A"],
            aaaa=buckets["AAAA"],
            cname=buckets["CNAME"],
            mx=buckets["MX"],
            ns=buckets["NS"],
            txt=buckets["TXT"],
            soa=buckets["SOA"],
            caa=buckets["CAA"],
            https=buckets["HTTPS"],
            svcb=buckets["SVCB"],
            errors=tuple(errors),
        )

    def _try_type(
        self,
        name: str,
        label: str,
        fatal: bool,
    ) -> tuple[tuple[DNSRecord, ...], tuple[str, str] | None]:
        try:
            records = tuple(self._resolve_label(name, label))
            return records, None
        except DomainNotFoundError:
            if fatal:
                raise
            return (), (label, f"NXDOMAIN for {label} (name exists for other types).")
        except DNSQueryError as exc:
            if fatal:
                raise
            return (), (label, str(exc))

    def _resolve_label(self, name: str, label: str) -> list[DNSRecord]:
        methods = {
            "A": self.resolve_a,
            "AAAA": self.resolve_aaaa,
            "CNAME": self.resolve_cname,
            "MX": self.resolve_mx,
            "NS": self.resolve_ns,
            "TXT": self.resolve_txt,
            "SOA": self.resolve_soa,
            "CAA": self.resolve_caa,
            "HTTPS": self.resolve_https,
            "SVCB": self.resolve_svcb,
        }
        return methods[label](name)

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

    def resolve_https(self, name: str) -> list[DNSRecord]:
        return self._query(name, "HTTPS")

    def resolve_svcb(self, name: str) -> list[DNSRecord]:
        return self._query(name, "SVCB")

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

    def inspect_mta_sts(self, name: str) -> MtaStsObservation:
        """TXT lookup at _mta-sts.<name>. Does not fetch the HTTPS policy."""
        qname = mta_sts_query_name(name)
        host = mta_sts_policy_host(name)
        try:
            records = self.resolve_txt(qname)
        except DomainNotFoundError:
            return evaluate_mta_sts(qname, host, ())
        except DNSQueryError as exc:
            return evaluate_mta_sts(qname, host, (), error=str(exc))
        return evaluate_mta_sts(qname, host, records)

    def inspect_tls_rpt(self, name: str) -> TlsRptObservation:
        """TXT lookup at _smtp._tls.<name>. Does not send SMTP or fetch rua URLs."""
        qname = tls_rpt_query_name(name)
        try:
            records = self.resolve_txt(qname)
        except DomainNotFoundError:
            return evaluate_tls_rpt(qname, ())
        except DNSQueryError as exc:
            return evaluate_tls_rpt(qname, (), error=str(exc))
        return evaluate_tls_rpt(qname, records)

    def inspect_bimi(self, name: str) -> BimiObservation:
        """TXT lookup at default._bimi.<name>. Does not fetch logo or VMC URLs."""
        qname = bimi_query_name(name)
        try:
            records = self.resolve_txt(qname)
        except DomainNotFoundError:
            return evaluate_bimi(qname, DEFAULT_SELECTOR, ())
        except DNSQueryError as exc:
            return evaluate_bimi(qname, DEFAULT_SELECTOR, (), error=str(exc))
        return evaluate_bimi(qname, DEFAULT_SELECTOR, records)

    def inspect_tlsa(self, name: str) -> TlsaObservation:
        """TLSA lookup at _443._tcp.<name>. Does not open TLS or follow MX."""
        qname = tlsa_query_name(name)
        try:
            records = self.resolve_tlsa(qname)
        except DomainNotFoundError:
            return evaluate_tlsa(qname, ())
        except DNSQueryError as exc:
            return evaluate_tlsa(qname, (), error=str(exc))
        return evaluate_tlsa(qname, records)

    def resolve_tlsa(self, name: str) -> list[DNSRecord]:
        return self._query(name, "TLSA")

    def inspect_sshfp(self, name: str) -> SshfpObservation:
        """SSHFP lookup at <name>. Does not open SSH or compare live keys."""
        host = name.rstrip(".").lower()
        try:
            records = self.resolve_sshfp(host)
        except DomainNotFoundError:
            return evaluate_sshfp(host, ())
        except DNSQueryError as exc:
            return evaluate_sshfp(host, (), error=str(exc))
        return evaluate_sshfp(host, records)

    def resolve_sshfp(self, name: str) -> list[DNSRecord]:
        return self._query(name, "SSHFP")

    def inspect_fcrdns(self, lookup: CoreLookup) -> FcrdnsObservation:
        """PTR then forward A/AAAA for each address. Does not contact the IP."""
        ips = _unique_ips(lookup)
        truncated = len(ips) > MAX_ADDRESSES
        checks = tuple(self._fcrdns_check(ip) for ip in ips[:MAX_ADDRESSES])
        return evaluate_fcrdns(checks, truncated=truncated)

    def _fcrdns_check(self, ip: str) -> FcrdnsCheck:
        qname = ptr_name(ip)
        try:
            ptr_records = self.resolve_reverse(ip)
        except DNSQueryError as exc:
            return FcrdnsCheck(
                ip=ip,
                ptr_query=qname,
                ptr_names=(),
                forward_ips=(),
                status="UNREADABLE",
                error=str(exc),
            )
        names = tuple(record.value.rstrip(".").lower() for record in ptr_records if record.value)
        if not names:
            return FcrdnsCheck(
                ip=ip,
                ptr_query=qname,
                ptr_names=(),
                forward_ips=(),
                status="NO PTR",
            )
        version = ipaddress.ip_address(ip).version
        forward: list[str] = []
        errors: list[str] = []
        for host in names:
            try:
                answers = self.resolve_a(host) if version == 4 else self.resolve_aaaa(host)
            except DomainNotFoundError:
                answers = []
            except DNSQueryError as exc:
                errors.append(str(exc))
                continue
            forward.extend(canonicalize_ip(record.value) for record in answers)
        forward_ips = tuple(dict.fromkeys(forward))
        target = canonicalize_ip(ip)
        if target in forward_ips:
            return FcrdnsCheck(
                ip=ip,
                ptr_query=qname,
                ptr_names=names,
                forward_ips=forward_ips,
                status="CONFIRMED",
            )
        if errors and not forward_ips:
            return FcrdnsCheck(
                ip=ip,
                ptr_query=qname,
                ptr_names=names,
                forward_ips=(),
                status="UNREADABLE",
                error="; ".join(errors),
            )
        return FcrdnsCheck(
            ip=ip,
            ptr_query=qname,
            ptr_names=names,
            forward_ips=forward_ips,
            status="MISMATCH",
        )

    def inspect_mx_hosts(self, name: str) -> MxHostObservation:
        """A/AAAA of each MX target. Does not open SMTP or contact the host."""
        host = name.rstrip(".").lower()
        try:
            records = self.resolve_mx(host)
        except DomainNotFoundError:
            return evaluate_mx_hosts(host, ())
        except DNSQueryError as exc:
            return evaluate_mx_hosts(host, (), error=str(exc))
        targets = unique_mx_hosts(records)
        truncated = len(targets) > MAX_HOSTS
        checks = tuple(
            self._mx_host_check(target, preference)
            for target, preference in targets[:MAX_HOSTS]
        )
        return evaluate_mx_hosts(host, checks, truncated=truncated)

    def _mx_host_check(self, host: str, preference: int | None) -> MxHostCheck:
        if mx_host_name(host) == ".":
            return MxHostCheck(
                host=".",
                preference=preference,
                ipv4=(),
                ipv6=(),
                status="NULL MX",
            )
        ipv4, err4, nx4 = self._lookup_host_ips(host, "A")
        ipv6, err6, nx6 = self._lookup_host_ips(host, "AAAA")
        if ipv4 or ipv6:
            return MxHostCheck(
                host=host,
                preference=preference,
                ipv4=ipv4,
                ipv6=ipv6,
                status="RESOLVES",
            )
        errors = [item for item in (err4, err6) if item]
        if errors:
            return MxHostCheck(
                host=host,
                preference=preference,
                ipv4=(),
                ipv6=(),
                status="UNREADABLE",
                error="; ".join(errors),
            )
        if nx4 or nx6:
            return MxHostCheck(
                host=host,
                preference=preference,
                ipv4=(),
                ipv6=(),
                status="NXDOMAIN",
            )
        return MxHostCheck(
            host=host,
            preference=preference,
            ipv4=(),
            ipv6=(),
            status="NO ADDRESS",
        )

    def inspect_ns_hosts(self, name: str) -> NsHostObservation:
        """A/AAAA of each NS target. Does not AXFR or contact the nameserver."""
        host = name.rstrip(".").lower()
        try:
            records = self.resolve_ns(host)
        except DomainNotFoundError:
            return evaluate_ns_hosts(host, ())
        except DNSQueryError as exc:
            return evaluate_ns_hosts(host, (), error=str(exc))
        targets = unique_ns_hosts(records)
        truncated = len(targets) > MAX_NS_HOSTS
        checks = tuple(
            self._ns_host_check(host, target) for target in targets[:MAX_NS_HOSTS]
        )
        return evaluate_ns_hosts(host, checks, truncated=truncated)

    def _ns_host_check(self, zone: str, ns_host: str) -> NsHostCheck:
        bailiwick = ns_in_bailiwick(zone, ns_host)
        ipv4, err4, nx4 = self._lookup_host_ips(ns_host, "A")
        ipv6, err6, nx6 = self._lookup_host_ips(ns_host, "AAAA")
        if ipv4 or ipv6:
            return NsHostCheck(
                host=ns_host,
                in_bailiwick=bailiwick,
                ipv4=ipv4,
                ipv6=ipv6,
                status="RESOLVES",
            )
        errors = [item for item in (err4, err6) if item]
        if errors:
            return NsHostCheck(
                host=ns_host,
                in_bailiwick=bailiwick,
                ipv4=(),
                ipv6=(),
                status="UNREADABLE",
                error="; ".join(errors),
            )
        if nx4 or nx6:
            return NsHostCheck(
                host=ns_host,
                in_bailiwick=bailiwick,
                ipv4=(),
                ipv6=(),
                status="NXDOMAIN",
            )
        return NsHostCheck(
            host=ns_host,
            in_bailiwick=bailiwick,
            ipv4=(),
            ipv6=(),
            status="NO ADDRESS",
        )

    def _lookup_host_ips(
        self, host: str, rdtype: str
    ) -> tuple[tuple[str, ...], str | None, bool]:
        try:
            answers = self.resolve_a(host) if rdtype == "A" else self.resolve_aaaa(host)
        except DomainNotFoundError:
            return (), None, True
        except DNSQueryError as exc:
            return (), str(exc), False
        ips = tuple(dict.fromkeys(canonicalize_ip(record.value) for record in answers))
        return ips, None, False

    def inspect_cname_targets(self, lookup: CoreLookup) -> CnameTargetObservation:
        """A/AAAA at the end of each CNAME. Does not fetch HTTP."""
        targets = unique_cname_targets(lookup.cname)
        truncated = len(targets) > MAX_TARGETS
        checks = tuple(self._cname_target_check(item) for item in targets[:MAX_TARGETS])
        return evaluate_cname_targets(checks, truncated=truncated)

    def _cname_target_check(self, target: str) -> CnameTargetCheck:
        current = cname_target_name(target)
        chain: list[str] = []
        hops = 0
        while hops < MAX_HOPS:
            if not current:
                return CnameTargetCheck(
                    target=target,
                    chain=tuple(chain),
                    ipv4=(),
                    ipv6=(),
                    status="NO ADDRESS",
                )
            if current in chain:
                return CnameTargetCheck(
                    target=target,
                    chain=tuple(chain),
                    ipv4=(),
                    ipv6=(),
                    status="LOOP",
                )
            chain.append(current)
            ipv4, err4, nx4 = self._lookup_host_ips(current, "A")
            ipv6, err6, nx6 = self._lookup_host_ips(current, "AAAA")
            aliases, errc, nxc = self._lookup_cnames(current)
            if ipv4 or ipv6:
                return CnameTargetCheck(
                    target=target,
                    chain=tuple(chain),
                    ipv4=ipv4,
                    ipv6=ipv6,
                    status="RESOLVES",
                )
            if aliases:
                current = aliases[0]
                hops += 1
                continue
            errors = [item for item in (err4, err6, errc) if item]
            if errors:
                return CnameTargetCheck(
                    target=target,
                    chain=tuple(chain),
                    ipv4=(),
                    ipv6=(),
                    status="UNREADABLE",
                    error="; ".join(errors),
                )
            if nx4 or nx6 or nxc:
                return CnameTargetCheck(
                    target=target,
                    chain=tuple(chain),
                    ipv4=(),
                    ipv6=(),
                    status="NXDOMAIN",
                )
            return CnameTargetCheck(
                target=target,
                chain=tuple(chain),
                ipv4=(),
                ipv6=(),
                status="NO ADDRESS",
            )
        return CnameTargetCheck(
            target=target,
            chain=tuple(chain),
            ipv4=(),
            ipv6=(),
            status="TOO DEEP",
            error="CNAME chain longer than 5 hops",
        )

    def _lookup_cnames(
        self, host: str
    ) -> tuple[tuple[str, ...], str | None, bool]:
        try:
            records = self.resolve_cname(host)
        except DomainNotFoundError:
            return (), None, True
        except DNSQueryError as exc:
            return (), str(exc), False
        names = tuple(
            dict.fromkeys(
                cname_target_name(record.value)
                for record in records
                if cname_target_name(record.value)
            )
        )
        return names, None, False

    def inspect_soa_ns(self, name: str) -> SoaNsObservation:
        """Compare SOA mname to the NS set. Does not AXFR or contact the primary."""
        host = name.rstrip(".").lower()
        try:
            soa_records = self.resolve_soa(host)
        except DomainNotFoundError:
            return evaluate_soa_ns(host, None, ())
        except DNSQueryError as exc:
            return evaluate_soa_ns(host, None, (), error=str(exc))
        primary = soa_primary(soa_records[0]) if soa_records else None
        serial = soa_serial(soa_records[0]) if soa_records else None
        try:
            ns_records = self.resolve_ns(host)
        except DomainNotFoundError:
            return evaluate_soa_ns(host, primary, (), serial=serial)
        except DNSQueryError as exc:
            return evaluate_soa_ns(host, primary, (), serial=serial, error=str(exc))
        return evaluate_soa_ns(
            host,
            primary,
            ns_names_from_records(ns_records),
            serial=serial,
        )

    def inspect_caa(self, name: str) -> CaaObservation:
        """Summarize CAA issue / issuewild / iodef. Does not contact CAs."""
        host = name.rstrip(".").lower()
        try:
            records = self.resolve_caa(host)
        except DomainNotFoundError:
            return evaluate_caa(host, ())
        except DNSQueryError as exc:
            return evaluate_caa(host, (), error=str(exc))
        return evaluate_caa(host, records)

    def inspect_dkim(self, name: str, selector: str) -> DkimObservation:
        """TXT lookup at <selector>._domainkey.<name>. Does not guess selectors."""
        qname = dkim_query_name(name, selector)
        try:
            records = self.resolve_txt(qname)
        except DomainNotFoundError:
            return evaluate_dkim(qname, selector, ())
        except DNSQueryError as exc:
            return evaluate_dkim(qname, selector, (), error=str(exc))
        return evaluate_dkim(qname, selector, records)

    def inspect_srv(self, name: str, spec: SrvSpec) -> SrvObservation:
        """SRV lookup at _service._proto.<name>. Does not guess services."""
        qname = srv_query_name(name, spec)
        try:
            records = self.resolve_srv(qname)
        except DomainNotFoundError:
            return evaluate_srv(qname, spec, ())
        except DNSQueryError as exc:
            return evaluate_srv(qname, spec, (), error=str(exc))
        return evaluate_srv(qname, spec, records)

    def resolve_srv(self, name: str) -> list[DNSRecord]:
        return self._query(name, "SRV")

    def expand_spf(self, observation: SpfObservation) -> SpfObservation:
        """Look up include:/redirect= one hop. Nested include: is listed, not queried."""
        return apply_spf_hops(observation, self._fetch_spf_txt)

    def _fetch_spf_txt(self, name: str) -> tuple[tuple[DNSRecord, ...], str | None]:
        try:
            return tuple(self.resolve_txt(name)), None
        except DomainNotFoundError:
            return (), None
        except DNSQueryError as exc:
            return (), str(exc)

    def inspect_dnssec(self, name: str) -> DnssecObservation:
        """Look for DNSKEY/DS and the AD flag. Failures become observations."""
        client = self._edns_client()
        errors: list[str] = []
        # Sequential on purpose: two queries, and tests mock probe order.
        dnskey_found, ad_key, dnskey_rdatas = self._unpack_dnssec_probe(
            self._dnssec_probe(client, name, "DNSKEY", errors)
        )
        ds_found, ad_ds, ds_rdatas = self._unpack_dnssec_probe(
            self._dnssec_probe(client, name, "DS", errors)
        )
        keys, keys_truncated = parse_dnskeys(dnskey_rdatas)
        delegations, delegations_truncated = parse_delegations(ds_rdatas)
        return evaluate_dnssec(
            dnskey_found=dnskey_found,
            ds_found=ds_found,
            ad_flag=ad_key or ad_ds,
            error="; ".join(errors) if errors else None,
            keys=keys,
            delegations=delegations,
            keys_truncated=keys_truncated,
            delegations_truncated=delegations_truncated,
        )

    @staticmethod
    def _unpack_dnssec_probe(
        result: tuple[object, ...],
    ) -> tuple[bool, bool, tuple[object, ...]]:
        """Accept 2-tuple mocks and 3-tuple probes that include rdata."""
        found = bool(result[0])
        ad_flag = bool(result[1])
        records = result[2] if len(result) > 2 else ()
        return found, ad_flag, tuple(records) if records else ()

    def _dnssec_probe(
        self,
        client: dns.resolver.Resolver,
        name: str,
        rdtype: str,
        errors: list[str],
    ) -> tuple[bool, bool, tuple[object, ...]]:
        _log.info("Querying %s record for %s", rdtype, name)
        try:
            answer = client.resolve(name, rdtype, search=False)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False, False, ()
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            _log.warning("DNS query timeout for %s %s", rdtype, name)
            errors.append(f"{rdtype} query timed out")
            return False, False, ()
        except dns.resolver.NoNameservers:
            _log.warning("No nameservers for %s %s", rdtype, name)
            errors.append(f"{rdtype} query had no nameservers")
            return False, False, ()
        except OSError:
            _log.warning("Network error for %s %s", rdtype, name)
            errors.append(f"{rdtype} query had a network error")
            return False, False, ()
        except dns.exception.DNSException:
            _log.warning("DNS query failed for %s %s", rdtype, name)
            errors.append(f"{rdtype} query failed")
            return False, False, ()

        response = getattr(answer, "response", None)
        ad_flag = bool(response is not None and (response.flags & dns.flags.AD))
        return True, ad_flag, self._probe_rdatas(answer)

    def _probe_rdatas(self, answer: object) -> tuple[object, ...]:
        """Collect rdata from a real Answer. MagicMock answers yield nothing."""
        collected: list[object] = []
        try:
            iterator = iter(answer)
        except TypeError:
            return ()
        for rdata in iterator:
            algorithm = getattr(rdata, "algorithm", None)
            if not isinstance(algorithm, int):
                break
            collected.append(rdata)
            if len(collected) >= MAX_DNSSEC_ITEMS + 1:
                break
        return tuple(collected)

    def _edns_client(self) -> dns.resolver.Resolver:
        """EDNS client for DNSSEC probes. Reuse nameservers; skip resolv.conf."""
        nameservers = list(self._client.nameservers)
        if nameservers:
            client = dns.resolver.Resolver(configure=False)
            client.nameservers = nameservers
        else:
            client = dns.resolver.Resolver(configure=True)
        client.timeout = self._client.timeout
        client.lifetime = self._client.lifetime
        client.use_edns(0, dns.flags.DO, 1232)
        return client

    def _apply_timeouts(self) -> None:
        """timeout = wait per nameserver; lifetime = budget for failover."""
        self._client.timeout = self.timeout
        count = max(1, len(self._client.nameservers))
        self._client.lifetime = self.timeout * min(count, 4)

    def _query(self, name: str, record_type: str) -> list[DNSRecord]:
        """Ask the recursive resolver for one record type.

        search=False prevents Windows/Linux search suffixes from turning
        example.com into example.com.company.local.
        """
        _log.info("Querying %s record for %s", record_type, name)
        try:
            # dnspython Resolver is not thread-safe; parallel lookups share this client.
            with self._lock:
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
