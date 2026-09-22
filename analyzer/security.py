"""Security analysis engine — observations, not CVEs.

Missing DNSSEC, SPF, DMARC, or CAA is a signal. It is not automatic proof
that the domain is vulnerable or compromised.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from analyzer.bimi import BimiObservation
from analyzer.dmarc import DmarcObservation
from analyzer.dkim import DkimObservation
from analyzer.dnssec import SHA1_DS_DIGEST, SHA1_ERA_ALGORITHMS, DnssecObservation
from analyzer.models import CoreLookup
from analyzer.mtasts import MtaStsObservation
from analyzer.records import describe_ip_scope
from analyzer.risk import RiskScore, score_risk
from analyzer.spf import SpfHop, SpfObservation
from analyzer.srv import SrvObservation
from analyzer.naptr import NaptrObservation
from analyzer.uri import UriObservation
from analyzer.dname import DnameObservation
from analyzer.ipseckey import IpseckeyObservation
from analyzer.smimea import SmimeaObservation
from analyzer.openpgpkey import OpenpgpkeyObservation
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

DISCLAIMER = (
    "Findings are configuration observations, not vulnerability scanner results. "
    "Missing a record does not automatically mean the domain is compromised."
)

_TXT_MANY = 8


@dataclass(frozen=True)
class SecurityFinding:
    severity: str
    title: str
    description: str
    recommendation: str
    code: str


@dataclass(frozen=True)
class SecurityReport:
    findings: tuple[SecurityFinding, ...]
    risk: RiskScore
    disclaimer: str = DISCLAIMER

    @property
    def highest_severity(self) -> str | None:
        if not self.findings:
            return None
        order = {"info": 0, "low": 1, "medium": 2, "high": 3}
        return max(self.findings, key=lambda item: order.get(item.severity, 0)).severity


class SecurityAnalyzer:
    """Build findings from lookup + DNSSEC/SPF/DMARC/DKIM/SRV/NAPTR/URI/DNAME/IPSECKEY/SMIMEA/OPENPGPKEY/MTA-STS/TLS-RPT/BIMI/TLSA/SSHFP/FCrDNS/MX-host/NS-host/CNAME-target/SOA-NS/CAA/CDS/NSEC/CSYNC/ZONEMD/RRSIG observations."""

    def analyze(
        self,
        lookup: CoreLookup,
        dnssec: DnssecObservation,
        spf: SpfObservation,
        dmarc: DmarcObservation,
        dkim: Sequence[DkimObservation] = (),
        srv: Sequence[SrvObservation] = (),
        mta_sts: MtaStsObservation | None = None,
        tls_rpt: TlsRptObservation | None = None,
        bimi: BimiObservation | None = None,
        tlsa: TlsaObservation | None = None,
        sshfp: SshfpObservation | None = None,
        fcrdns: FcrdnsObservation | None = None,
        mx_hosts: MxHostObservation | None = None,
        ns_hosts: NsHostObservation | None = None,
        cname_targets: CnameTargetObservation | None = None,
        soa_ns: SoaNsObservation | None = None,
        caa: CaaObservation | None = None,
        naptr: NaptrObservation | None = None,
        uri: UriObservation | None = None,
        dname: DnameObservation | None = None,
        ipseckey: IpseckeyObservation | None = None,
        smimea: Sequence[SmimeaObservation] = (),
        openpgpkey: Sequence[OpenpgpkeyObservation] = (),
        cds: CdsObservation | None = None,
        nsec: NsecObservation | None = None,
        csync: CsyncObservation | None = None,
        zonemd: ZonemdObservation | None = None,
        rrsig: RrsigObservation | None = None,
    ) -> SecurityReport:
        findings: list[SecurityFinding] = []
        findings.extend(self._dnssec(dnssec))
        findings.extend(self._spf(spf))
        findings.extend(self._dmarc(dmarc))
        findings.extend(self._dkim(dkim))
        findings.extend(self._srv(srv))
        if naptr is not None:
            findings.extend(self._naptr(naptr))
        if uri is not None:
            findings.extend(self._uri(uri))
        if dname is not None:
            findings.extend(self._dname(dname))
        if ipseckey is not None:
            findings.extend(self._ipseckey(ipseckey))
        findings.extend(self._smimea(smimea))
        findings.extend(self._openpgpkey(openpgpkey))
        if cds is not None:
            findings.extend(self._cds(cds))
        if nsec is not None:
            findings.extend(self._nsec(nsec))
        if csync is not None:
            findings.extend(self._csync(csync))
        if zonemd is not None:
            findings.extend(self._zonemd(zonemd))
        if rrsig is not None:
            findings.extend(self._rrsig(rrsig))
        if mta_sts is not None:
            findings.extend(self._mta_sts(mta_sts))
        if tls_rpt is not None:
            findings.extend(self._tls_rpt(tls_rpt))
        if bimi is not None:
            findings.extend(self._bimi(bimi, dmarc))
        if tlsa is not None:
            findings.extend(self._tlsa(tlsa))
        if sshfp is not None:
            findings.extend(self._sshfp(sshfp))
        if fcrdns is not None:
            findings.extend(self._fcrdns(fcrdns))
        if mx_hosts is not None:
            findings.extend(self._mx_hosts(mx_hosts))
        if ns_hosts is not None:
            findings.extend(self._ns_hosts(ns_hosts))
        if soa_ns is not None:
            findings.extend(self._soa_ns(soa_ns))
        if caa is not None:
            findings.extend(self._caa_observation(caa))
        else:
            findings.extend(self._caa(lookup))
        findings.extend(self._addresses(lookup))
        if cname_targets is not None:
            findings.extend(self._cname_targets(cname_targets))
        else:
            findings.extend(self._cname(lookup))
        findings.extend(self._txt_volume(lookup))
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        findings.sort(key=lambda item: (order.get(item.severity, 9), item.title))
        return SecurityReport(
            findings=tuple(findings),
            risk=score_risk(findings),
        )

    def _dnssec(self, dnssec: DnssecObservation) -> list[SecurityFinding]:
        if dnssec.status == "DETECTED":
            findings: list[SecurityFinding] = []
            if any(key.algorithm in SHA1_ERA_ALGORITHMS for key in dnssec.keys):
                findings.append(
                    SecurityFinding(
                        severity="info",
                        title="DNSKEY uses a SHA-1-era algorithm",
                        description=(
                            "At least one DNSKEY uses algorithm 1, 3, 5, 6, or 7 "
                            "(MD5/SHA-1 era). That is a deprecated algorithm family, "
                            "not proof that the zone is compromised."
                        ),
                        recommendation=(
                            "Operators typically migrate to RSA/SHA-256, ECDSA, or "
                            "Ed25519. This listing is not a chain-of-trust validation."
                        ),
                        code="dnssec_sha1_algorithm",
                    )
                )
            if any(item.digest_type == SHA1_DS_DIGEST for item in dnssec.delegations):
                findings.append(
                    SecurityFinding(
                        severity="info",
                        title="DS uses SHA-1 digest",
                        description=(
                            "A DS record uses digest type 1 (SHA-1). That digest is "
                            "deprecated. It is not a compromise and this tool does "
                            "not validate the delegation."
                        ),
                        recommendation=(
                            "Prefer DS digest type 2 (SHA-256) at the parent. "
                            "SHA-1 DS is an observation, not a breach."
                        ),
                        code="dnssec_sha1_ds",
                    )
                )
            return findings
        if dnssec.error:
            return []
        return [
            SecurityFinding(
                severity="info",
                title="DNSSEC not detected by this resolver",
                description=(
                    "No DNSKEY or DS was visible here. The zone may still be signed; "
                    "some resolvers strip DNSSEC records or never set the AD flag."
                ),
                recommendation=(
                    "If you operate the domain, confirm DNSKEY/DS at the registrar "
                    "and test with a validating resolver. Absence is not a compromise."
                ),
                code="dnssec_not_detected",
            )
        ]

    def _spf(self, spf: SpfObservation) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        if spf.error:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="SPF could not be read",
                    description=(
                        f"{spf.error} A timeout or TXT failure is not the same as "
                        "a missing policy, and it is not a compromise."
                    ),
                    recommendation="Retry the TXT lookup before treating SPF as unpublished.",
                    code="spf_unreadable",
                )
            )
            return findings
        if spf.status != "FOUND":
            findings.append(
                SecurityFinding(
                    severity="low",
                    title="SPF not published",
                    description=(
                        "No v=spf1 TXT record was found. Receivers cannot check "
                        "which hosts may send mail for this name. This is a missing "
                        "policy signal, not proof of an incident."
                    ),
                    recommendation=(
                        "If this name sends mail, publish a single v=spf1 record. "
                        "If it does not send mail, v=spf1 -all is a common choice."
                    ),
                    code="spf_missing",
                )
            )
            return findings
        if spf.multiple_records:
            findings.append(
                SecurityFinding(
                    severity="medium",
                    title="Multiple SPF records",
                    description=(
                        "RFC 7208 allows one v=spf1 string per name. Multiple records "
                        "often cause a permanent SPF error at receivers."
                    ),
                    recommendation="Keep a single v=spf1 TXT record and merge mechanisms.",
                    code="spf_multiple",
                )
            )
        if spf.all_term in {"+all", "all"}:
            findings.append(
                SecurityFinding(
                    severity="medium",
                    title="SPF +all allows any sender",
                    description=(
                        "The policy ends with +all (or bare all), so any host may pass SPF. "
                        "That does not authenticate mail; it mainly disables SPF as a filter."
                    ),
                    recommendation="Replace +all with ~all or -all unless you have a rare reason not to.",
                    code="spf_plus_all",
                )
            )
        for hop in spf.hops:
            findings.extend(self._spf_hop(hop))
        return findings

    def _spf_hop(self, hop: SpfHop) -> list[SecurityFinding]:
        if hop.error:
            return [
                SecurityFinding(
                    severity="info",
                    title=f"SPF {hop.kind} {hop.domain} could not be read",
                    description=(
                        f"{hop.error} A timeout on an include: target is not the same "
                        "as a missing apex SPF record, and it is not a compromise."
                    ),
                    recommendation="Retry the include lookup before treating the chain as broken.",
                    code="spf_include_unreadable",
                )
            ]
        if hop.status != "FOUND":
            return [
                SecurityFinding(
                    severity="low",
                    title=f"SPF {hop.kind} {hop.domain} has no v=spf1 record",
                    description=(
                        "RFC 7208 treats a void include: as a permanent SPF error. "
                        "This is a policy-chain signal, not proof of compromise."
                    ),
                    recommendation=(
                        "Publish v=spf1 at the include: name, or remove the include: "
                        "from the apex policy."
                    ),
                    code="spf_include_missing",
                )
            ]
        return []

    def _dmarc(self, dmarc: DmarcObservation) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        if dmarc.error and dmarc.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="DMARC could not be read",
                    description=(
                        f"{dmarc.error} A lookup failure is not the same as a missing "
                        "policy, and it is not a compromise."
                    ),
                    recommendation="Retry the _dmarc lookup before treating DMARC as unpublished.",
                    code="dmarc_unreadable",
                )
            ]
        if dmarc.status != "FOUND":
            findings.append(
                SecurityFinding(
                    severity="low",
                    title="DMARC not published",
                    description=(
                        f"No v=DMARC1 record at {dmarc.query_name}. Receivers have no "
                        "domain-owner policy for unaligned mail. This is not an automatic "
                        "critical vulnerability."
                    ),
                    recommendation=(
                        "If you own the domain, consider _dmarc with p=none plus rua "
                        "for reporting, then quarantine/reject when ready."
                    ),
                    code="dmarc_missing",
                )
            )
            return findings
        if dmarc.multiple_records:
            findings.append(
                SecurityFinding(
                    severity="medium",
                    title="Multiple DMARC records",
                    description=(
                        "More than one v=DMARC1 TXT string was returned. Receivers may "
                        "treat that as an invalid policy and ignore DMARC."
                    ),
                    recommendation="Keep a single v=DMARC1 record at _dmarc.<domain>.",
                    code="dmarc_multiple",
                )
            )
        if dmarc.policy == "none":
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="DMARC policy is p=none",
                    description=(
                        "p=none monitors and reports; it does not change delivery. "
                        "Spoofed mail can still be accepted."
                    ),
                    recommendation=(
                        "Use rua reports, then move to quarantine or reject when legitimate "
                        "mail is aligned."
                    ),
                    code="dmarc_p_none",
                )
            )
        return findings

    def _dkim(self, observations: Sequence[DkimObservation]) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        for item in observations:
            if item.error:
                findings.append(
                    SecurityFinding(
                        severity="info",
                        title=f"DKIM selector {item.selector} could not be read",
                        description=(
                            f"{item.error} A timeout is not the same as a missing key, "
                            "and it is not a compromise."
                        ),
                        recommendation="Retry the lookup before treating this selector as unpublished.",
                        code="dkim_unreadable",
                    )
                )
                continue
            if item.status == "NOT DETECTED":
                findings.append(
                    SecurityFinding(
                        severity="info",
                        title=f"DKIM selector {item.selector} not published",
                        description=(
                            f"No v=DKIM1 TXT was found at {item.query_name}. "
                            "The selector may be unused, misspelled, or unpublished. "
                            "This is not proof that all mail is unsigned."
                        ),
                        recommendation=(
                            "Confirm the selector from a signed message's DKIM-Signature "
                            "header. This tool does not guess selector names."
                        ),
                        code="dkim_selector_missing",
                    )
                )
                continue
            if item.revoked:
                findings.append(
                    SecurityFinding(
                        severity="medium",
                        title=f"DKIM selector {item.selector} is revoked",
                        description=(
                            f"{item.query_name} has an empty p= tag. Receivers treat "
                            "that selector as revoked. This is a key lifecycle signal, "
                            "not proof of compromise."
                        ),
                        recommendation=(
                            "If the selector is retired, keep p= empty. If mail still "
                            "uses it, publish a new public key."
                        ),
                        code="dkim_revoked",
                    )
                )
            if item.multiple_records:
                findings.append(
                    SecurityFinding(
                        severity="low",
                        title=f"Multiple DKIM records for selector {item.selector}",
                        description=(
                            "More than one v=DKIM1 TXT was found at this selector. "
                            "Receivers may concatenate or ignore extra records."
                        ),
                        recommendation="Keep one DKIM TXT RR per selector (strings may still split).",
                        code="dkim_multiple",
                    )
                )
        return findings

    def _srv(self, observations: Sequence[SrvObservation]) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        for item in observations:
            label = f"{item.service}/{item.protocol}"
            if item.error:
                findings.append(
                    SecurityFinding(
                        severity="info",
                        title=f"SRV {label} could not be read",
                        description=(
                            f"{item.error} A timeout is not the same as a missing "
                            "service, and it is not a compromise."
                        ),
                        recommendation="Retry the lookup before treating this service as unpublished.",
                        code="srv_unreadable",
                    )
                )
                continue
            if item.status == "NOT DETECTED":
                findings.append(
                    SecurityFinding(
                        severity="info",
                        title=f"SRV {label} not published",
                        description=(
                            f"No SRV record was found at {item.query_name}. "
                            "The service may be unused, misspelled, or unpublished. "
                            "This is not proof that the host offers nothing."
                        ),
                        recommendation=(
                            "Confirm the service name from the application "
                            "(for example sip, xmpp, minecraft). This tool does "
                            "not guess SRV names."
                        ),
                        code="srv_missing",
                    )
                )
        return findings

    def _naptr(self, observation: NaptrObservation) -> list[SecurityFinding]:
        if observation.error:
            return [
                SecurityFinding(
                    severity="info",
                    title="NAPTR could not be read",
                    description=(
                        f"{observation.error} A timeout is not the same as a missing "
                        "NAPTR set, and it is not a compromise."
                    ),
                    recommendation="Retry the lookup before treating NAPTR as unpublished.",
                    code="naptr_unreadable",
                )
            ]
        if observation.status == "NOT DETECTED":
            return [
                SecurityFinding(
                    severity="info",
                    title="NAPTR not published",
                    description=(
                        f"No NAPTR record was found at {observation.query_name}. "
                        "Most names do not publish NAPTR. This is not proof that "
                        "ENUM, SIP, or another application is unused."
                    ),
                    recommendation=(
                        "Use --naptr only when you expect rewrite records at this "
                        "name. This tool does not guess ENUM or SIP applications."
                    ),
                    code="naptr_missing",
                )
            ]
        return []

    def _uri(self, observation: UriObservation) -> list[SecurityFinding]:
        if observation.error:
            return [
                SecurityFinding(
                    severity="info",
                    title="URI could not be read",
                    description=(
                        f"{observation.error} A timeout is not the same as a missing "
                        "URI set, and it is not a compromise."
                    ),
                    recommendation="Retry the lookup before treating URI as unpublished.",
                    code="uri_unreadable",
                )
            ]
        if observation.status == "NOT DETECTED":
            return [
                SecurityFinding(
                    severity="info",
                    title="URI not published",
                    description=(
                        f"No URI record was found at {observation.query_name}. "
                        "Most names do not publish URI. This is not proof that "
                        "a service or web path is unused."
                    ),
                    recommendation=(
                        "Use --uri only when you expect URI records at this name. "
                        "This tool does not guess prefixes such as _http._tcp "
                        "and does not fetch the target."
                    ),
                    code="uri_missing",
                )
            ]
        return []

    def _dname(self, observation: DnameObservation) -> list[SecurityFinding]:
        if observation.error:
            return [
                SecurityFinding(
                    severity="info",
                    title="DNAME could not be read",
                    description=(
                        f"{observation.error} A timeout is not the same as a missing "
                        "DNAME set, and it is not a compromise."
                    ),
                    recommendation="Retry the lookup before treating DNAME as unpublished.",
                    code="dname_unreadable",
                )
            ]
        if observation.status == "NOT DETECTED":
            return [
                SecurityFinding(
                    severity="info",
                    title="DNAME not published",
                    description=(
                        f"No DNAME record was found at {observation.query_name}. "
                        "Most names do not publish DNAME. This is not proof that "
                        "a subtree is unused."
                    ),
                    recommendation=(
                        "Use --dname only when you expect a subtree redirect at this "
                        "name. This tool does not synthesize CNAME records or walk "
                        "names under this node."
                    ),
                    code="dname_missing",
                )
            ]
        return []

    def _ipseckey(self, observation: IpseckeyObservation) -> list[SecurityFinding]:
        if observation.error:
            return [
                SecurityFinding(
                    severity="info",
                    title="IPSECKEY could not be read",
                    description=(
                        f"{observation.error} A timeout is not the same as a missing "
                        "IPSECKEY set, and it is not a compromise."
                    ),
                    recommendation=(
                        "Retry the lookup before treating IPSECKEY as unpublished."
                    ),
                    code="ipseckey_unreadable",
                )
            ]
        if observation.status == "NOT DETECTED":
            return [
                SecurityFinding(
                    severity="info",
                    title="IPSECKEY not published",
                    description=(
                        f"No IPSECKEY record was found at {observation.query_name}. "
                        "Most names do not publish IPSECKEY. This is not proof that "
                        "IPsec is unused or misconfigured."
                    ),
                    recommendation=(
                        "Use --ipseckey only when you expect IPsec gateway records "
                        "at this name. This tool does not probe IPsec or IKE, "
                        "does not dump key material, and does not resolve a "
                        "gateway domain name."
                    ),
                    code="ipseckey_missing",
                )
            ]
        return []

    def _smimea(self, observations: Sequence[SmimeaObservation]) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        for item in observations:
            if item.error:
                findings.append(
                    SecurityFinding(
                        severity="info",
                        title=f"SMIMEA for {item.local_part} could not be read",
                        description=(
                            f"{item.error} A timeout is not the same as a missing "
                            "SMIMEA record, and it is not a compromise."
                        ),
                        recommendation=(
                            "Retry the lookup before treating this local-part as "
                            "unpublished. This tool does not guess mailbox names."
                        ),
                        code="smimea_unreadable",
                    )
                )
                continue
            if item.status == "NOT DETECTED":
                findings.append(
                    SecurityFinding(
                        severity="info",
                        title=f"SMIMEA for {item.local_part} not published",
                        description=(
                            f"No SMIMEA record was found at {item.query_name}. "
                            "Most mailboxes do not publish SMIMEA. This is not proof "
                            "that S/MIME is unused or that the domain is compromised."
                        ),
                        recommendation=(
                            "Use --smimea only for a local-part you already know. "
                            "This tool does not guess mailboxes, does not send email, "
                            "and does not fetch certificates."
                        ),
                        code="smimea_missing",
                    )
                )
        return findings

    def _openpgpkey(
        self, observations: Sequence[OpenpgpkeyObservation]
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        for item in observations:
            if item.error:
                findings.append(
                    SecurityFinding(
                        severity="info",
                        title=f"OPENPGPKEY for {item.local_part} could not be read",
                        description=(
                            f"{item.error} A timeout is not the same as a missing "
                            "OPENPGPKEY record, and it is not a compromise."
                        ),
                        recommendation=(
                            "Retry the lookup before treating this local-part as "
                            "unpublished. This tool does not guess mailbox names."
                        ),
                        code="openpgpkey_unreadable",
                    )
                )
                continue
            if item.status == "NOT DETECTED":
                findings.append(
                    SecurityFinding(
                        severity="info",
                        title=f"OPENPGPKEY for {item.local_part} not published",
                        description=(
                            f"No OPENPGPKEY record was found at {item.query_name}. "
                            "Most mailboxes do not publish OPENPGPKEY. This is not "
                            "proof that OpenPGP is unused or that the domain is "
                            "compromised."
                        ),
                        recommendation=(
                            "Use --openpgpkey only for a local-part you already "
                            "know. This tool does not guess mailboxes, does not "
                            "contact a keyserver, and does not dump key bytes."
                        ),
                        code="openpgpkey_missing",
                    )
                )
        return findings

    def _cds(self, observation: CdsObservation) -> list[SecurityFinding]:
        if observation.error and observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="CDS/CDNSKEY could not be read",
                    description=(
                        f"{observation.error} A timeout is not the same as a missing "
                        "CDS set, and it is not broken DNSSEC or a compromise."
                    ),
                    recommendation=(
                        "Retry the CDS/CDNSKEY lookup before treating child-to-parent "
                        "DS signaling as unpublished."
                    ),
                    code="cds_unreadable",
                )
            ]
        if observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="CDS/CDNSKEY not published",
                    description=(
                        f"No CDS or CDNSKEY record at {observation.query_name}. "
                        "Absence is common for signed and unsigned zones. "
                        "This is not broken DNSSEC and is not a compromise."
                    ),
                    recommendation=(
                        "CDS/CDNSKEY are optional child-to-parent DS signals "
                        "(RFC 7344). This tool does not contact the parent "
                        "registry or submit a DS update."
                    ),
                    code="cds_missing",
                )
            ]
        return []

    def _nsec(self, observation: NsecObservation) -> list[SecurityFinding]:
        if observation.error and observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="NSEC/NSEC3PARAM could not be read",
                    description=(
                        f"{observation.error} A timeout is not the same as a missing "
                        "NSEC set, and it is not broken DNSSEC or a compromise."
                    ),
                    recommendation=(
                        "Retry the NSEC/NSEC3PARAM lookup before treating "
                        "authenticated denial as unpublished."
                    ),
                    code="nsec_unreadable",
                )
            ]
        if observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="NSEC/NSEC3PARAM not published",
                    description=(
                        f"No NSEC or NSEC3PARAM record at {observation.query_name}. "
                        "Unsigned zones typically publish neither. "
                        "This is not broken DNSSEC and is not a compromise."
                    ),
                    recommendation=(
                        "NSEC/NSEC3PARAM describe authenticated denial of existence. "
                        "This tool does not walk the NSEC/NSEC3 chain or query NSEC3."
                    ),
                    code="nsec_missing",
                )
            ]
        return []

    def _csync(self, observation: CsyncObservation) -> list[SecurityFinding]:
        if observation.error and observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="CSYNC could not be read",
                    description=(
                        f"{observation.error} A timeout is not the same as a missing "
                        "CSYNC set, and it is not broken DNS or a compromise."
                    ),
                    recommendation=(
                        "Retry the CSYNC lookup before treating child-to-parent "
                        "NS signaling as unpublished."
                    ),
                    code="csync_unreadable",
                )
            ]
        if observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="CSYNC not published",
                    description=(
                        f"No CSYNC record at {observation.query_name}. "
                        "Absence is common. This is not broken DNS and is not "
                        "a compromise."
                    ),
                    recommendation=(
                        "CSYNC is optional child-to-parent NS/A/AAAA signaling "
                        "(RFC 7477). This tool does not contact the parent "
                        "registry or update parent delegation."
                    ),
                    code="csync_missing",
                )
            ]
        return []

    def _zonemd(self, observation: ZonemdObservation) -> list[SecurityFinding]:
        if observation.error and observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="ZONEMD could not be read",
                    description=(
                        f"{observation.error} A timeout is not the same as a missing "
                        "ZONEMD set, and it is not broken DNSSEC or a compromise."
                    ),
                    recommendation=(
                        "Retry the ZONEMD lookup before treating the zone digest "
                        "as unpublished."
                    ),
                    code="zonemd_unreadable",
                )
            ]
        if observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="ZONEMD not published",
                    description=(
                        f"No ZONEMD record at {observation.query_name}. "
                        "Absence is common. This is not broken DNSSEC and is not "
                        "a compromise."
                    ),
                    recommendation=(
                        "ZONEMD is an optional zone digest (RFC 8976). "
                        "This tool does not AXFR the zone or recompute the digest."
                    ),
                    code="zonemd_missing",
                )
            ]
        return []

    def _rrsig(self, observation: RrsigObservation) -> list[SecurityFinding]:
        if observation.error and observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="RRSIG could not be read",
                    description=(
                        f"{observation.error} A timeout is not the same as a missing "
                        "RRSIG set, and it is not broken DNSSEC or a compromise."
                    ),
                    recommendation=(
                        "Retry the RRSIG lookup before treating signatures as unpublished."
                    ),
                    code="rrsig_unreadable",
                )
            ]
        if observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="RRSIG not published",
                    description=(
                        f"No RRSIG record at {observation.query_name}. "
                        "Absence is common on unsigned zones. This is not broken "
                        "DNSSEC and is not a compromise."
                    ),
                    recommendation=(
                        "RRSIG is the DNSSEC signature over an RRset (RFC 4034). "
                        "This tool lists signatures; it does not validate them."
                    ),
                    code="rrsig_missing",
                )
            ]
        return []

    def _mta_sts(self, observation: MtaStsObservation) -> list[SecurityFinding]:
        if observation.error and observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="MTA-STS could not be read",
                    description=(
                        f"{observation.error} A timeout is not the same as a missing "
                        "policy, and it is not a compromise."
                    ),
                    recommendation="Retry the _mta-sts lookup before treating MTA-STS as unpublished.",
                    code="mtasts_unreadable",
                )
            ]
        if observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="MTA-STS TXT not published",
                    description=(
                        f"No v=STSv1 record at {observation.query_name}. "
                        "Receivers cannot discover an MTA-STS policy id here. "
                        "This is common and is not proof that SMTP is unencrypted."
                    ),
                    recommendation=(
                        "If you operate inbound mail, publish v=STSv1; id=... at "
                        "_mta-sts and a HTTPS policy at mta-sts.<domain>. This tool "
                        "does not fetch that file."
                    ),
                    code="mtasts_missing",
                )
            ]
        findings: list[SecurityFinding] = []
        if observation.multiple_records:
            findings.append(
                SecurityFinding(
                    severity="low",
                    title="Multiple MTA-STS TXT records",
                    description=(
                        "More than one v=STSv1 TXT was returned. Receivers may "
                        "ignore the policy id."
                    ),
                    recommendation="Keep a single v=STSv1 record at _mta-sts.<domain>.",
                    code="mtasts_multiple",
                )
            )
        if not observation.policy_id:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="MTA-STS TXT has no id=",
                    description=(
                        "RFC 8461 requires an id= token so senders can notice "
                        "HTTPS policy changes. Absence is a configuration signal, "
                        "not a compromise."
                    ),
                    recommendation="Add id= to the v=STSv1 TXT and bump it when the policy file changes.",
                    code="mtasts_id_missing",
                )
            )
        return findings

    def _tls_rpt(self, observation: TlsRptObservation) -> list[SecurityFinding]:
        if observation.error and observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="TLS-RPT could not be read",
                    description=(
                        f"{observation.error} A timeout is not the same as a missing "
                        "report address, and it is not a compromise."
                    ),
                    recommendation="Retry the _smtp._tls lookup before treating TLS-RPT as unpublished.",
                    code="tlsrpt_unreadable",
                )
            ]
        if observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="TLS-RPT TXT not published",
                    description=(
                        f"No v=TLSRPTv1 record at {observation.query_name}. "
                        "Senders have no published address for SMTP TLS failure reports. "
                        "This is common and is not proof that STARTTLS is unused."
                    ),
                    recommendation=(
                        "If you operate inbound mail, publish v=TLSRPTv1; rua=mailto:... "
                        "at _smtp._tls.<domain>. This tool does not send those reports."
                    ),
                    code="tlsrpt_missing",
                )
            ]
        findings: list[SecurityFinding] = []
        if observation.multiple_records:
            findings.append(
                SecurityFinding(
                    severity="low",
                    title="Multiple TLS-RPT TXT records",
                    description=(
                        "More than one v=TLSRPTv1 TXT was returned. Senders may "
                        "ignore the report address."
                    ),
                    recommendation="Keep a single v=TLSRPTv1 record at _smtp._tls.<domain>.",
                    code="tlsrpt_multiple",
                )
            )
        if not observation.rua:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="TLS-RPT TXT has no rua=",
                    description=(
                        "RFC 8460 requires rua= (mailto: or https:) so senders know "
                        "where to deliver TLS reports. Absence is a configuration "
                        "signal, not a compromise."
                    ),
                    recommendation="Add rua=mailto:... or rua=https:... to the v=TLSRPTv1 TXT.",
                    code="tlsrpt_rua_missing",
                )
            )
        return findings

    def _bimi(
        self,
        observation: BimiObservation,
        dmarc: DmarcObservation,
    ) -> list[SecurityFinding]:
        if observation.error and observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="BIMI could not be read",
                    description=(
                        f"{observation.error} A timeout is not the same as a missing "
                        "logo record, and it is not a compromise."
                    ),
                    recommendation="Retry the default._bimi lookup before treating BIMI as unpublished.",
                    code="bimi_unreadable",
                )
            ]
        if observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="BIMI TXT not published",
                    description=(
                        f"No v=BIMI1 record at {observation.query_name}. "
                        "Only the default selector is queried. This is common "
                        "and is not proof that mail is unbranded or compromised."
                    ),
                    recommendation=(
                        "If you want BIMI, publish v=BIMI1; l=https://... at "
                        "default._bimi and keep DMARC at quarantine or reject. "
                        "This tool does not fetch the logo."
                    ),
                    code="bimi_missing",
                )
            ]
        findings: list[SecurityFinding] = []
        if observation.multiple_records:
            findings.append(
                SecurityFinding(
                    severity="low",
                    title="Multiple BIMI TXT records",
                    description=(
                        "More than one v=BIMI1 TXT was returned. Receivers may "
                        "ignore the logo record."
                    ),
                    recommendation="Keep a single v=BIMI1 record at default._bimi.<domain>.",
                    code="bimi_multiple",
                )
            )
        if not observation.location:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="BIMI TXT has no l=",
                    description=(
                        "BIMI needs an l= HTTPS URL for the SVG logo. Absence is "
                        "a configuration signal, not a compromise. The URL is not fetched."
                    ),
                    recommendation="Add l=https://... to the v=BIMI1 TXT (SVG, not a raster image).",
                    code="bimi_location_missing",
                )
            )
        enforcing = dmarc.status == "FOUND" and dmarc.policy in {"quarantine", "reject"}
        if not enforcing:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="BIMI published without enforcing DMARC",
                    description=(
                        "A BIMI TXT is visible, but DMARC is missing or p=none. "
                        "Most inboxes will not show the logo without quarantine or reject. "
                        "This is not a compromise."
                    ),
                    recommendation="Keep BIMI only after DMARC p=quarantine or p=reject is in place.",
                    code="bimi_without_enforcing_dmarc",
                )
            )
        return findings

    def _tlsa(self, observation: TlsaObservation) -> list[SecurityFinding]:
        if observation.error and observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="DANE TLSA could not be read",
                    description=(
                        f"{observation.error} A timeout is not the same as a missing "
                        "TLSA record, and it is not a compromise."
                    ),
                    recommendation="Retry the _443._tcp TLSA lookup before treating DANE as unpublished.",
                    code="tlsa_unreadable",
                )
            ]
        if observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="DANE TLSA not published",
                    description=(
                        f"No TLSA record at {observation.query_name}. "
                        "Only 443/tcp (HTTPS) is queried. Absence is common; "
                        "most sites still use public CAs only. This is not a compromise."
                    ),
                    recommendation=(
                        "If you want DANE, publish TLSA at _443._tcp.<domain>. "
                        "This tool does not open TLS or check the live certificate."
                    ),
                    code="tlsa_missing",
                )
            ]
        return []

    def _sshfp(self, observation: SshfpObservation) -> list[SecurityFinding]:
        if observation.error and observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="SSHFP could not be read",
                    description=(
                        f"{observation.error} A timeout is not the same as a missing "
                        "SSHFP record, and it is not a compromise."
                    ),
                    recommendation="Retry the SSHFP lookup before treating host-key fingerprints as unpublished.",
                    code="sshfp_unreadable",
                )
            ]
        if observation.status != "FOUND":
            return [
                SecurityFinding(
                    severity="info",
                    title="SSHFP not published",
                    description=(
                        f"No SSHFP record at {observation.query_name}. "
                        "Absence is common for names that are not SSH hosts. "
                        "This is not a compromise, and it does not mean SSH is open or closed."
                    ),
                    recommendation=(
                        "If this hostname is an SSH server, publish SSHFP and keep DNSSEC "
                        "visible to validating resolvers. This tool does not open port 22."
                    ),
                    code="sshfp_missing",
                )
            ]
        return []

    def _fcrdns(self, observation: FcrdnsObservation) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        unread = [item.ip for item in observation.checks if item.status == "UNREADABLE"]
        missing = [item.ip for item in observation.checks if item.status == "NO PTR"]
        mismatch = [item.ip for item in observation.checks if item.status == "MISMATCH"]
        if unread:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="FCrDNS could not be read for some addresses",
                    description=(
                        "PTR or forward lookup timed out for: "
                        + ", ".join(unread)
                        + ". A timeout is not a missing PTR, and it is not a compromise."
                    ),
                    recommendation="Retry the reverse lookup before treating FCrDNS as unpublished.",
                    code="fcrdns_unreadable",
                )
            )
        if missing:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="No PTR for some addresses",
                    description=(
                        "These A/AAAA addresses have no PTR: "
                        + ", ".join(missing)
                        + ". Missing reverse DNS is common and is not a compromise."
                    ),
                    recommendation=(
                        "If you operate the addresses, a PTR can help mail and ops. "
                        "This tool does not contact the IP."
                    ),
                    code="fcrdns_no_ptr",
                )
            )
        if mismatch:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="FCrDNS mismatch",
                    description=(
                        "PTR exists, but the forward lookup does not return the same IP: "
                        + ", ".join(mismatch)
                        + ". This can be CDN, shared hosting, or split-horizon — "
                        "not proof of hijacking."
                    ),
                    recommendation="Compare PTR and A/AAAA only if you expect them to match.",
                    code="fcrdns_mismatch",
                )
            )
        return findings

    def _mx_hosts(self, observation: MxHostObservation) -> list[SecurityFinding]:
        if observation.status == "UNREADABLE":
            return [
                SecurityFinding(
                    severity="info",
                    title="MX hosts could not be read",
                    description=(
                        "The MX lookup timed out or failed. A timeout is not a missing "
                        "mail host, and it is not a compromise."
                    ),
                    recommendation="Retry the MX lookup before treating mail routing as unpublished.",
                    code="mx_unreadable",
                )
            ]
        findings: list[SecurityFinding] = []
        unread = [item.host for item in observation.checks if item.status == "UNREADABLE"]
        missing = [item.host for item in observation.checks if item.status == "NXDOMAIN"]
        empty = [item.host for item in observation.checks if item.status == "NO ADDRESS"]
        if unread:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="Some MX hosts could not be read",
                    description=(
                        "A/AAAA lookup timed out for: "
                        + ", ".join(unread)
                        + ". A timeout is not a missing address, and it is not a compromise."
                    ),
                    recommendation="Retry the host lookup before treating the MX target as unpublished.",
                    code="mx_host_unreadable",
                )
            )
        if missing:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="MX target does not exist",
                    description=(
                        "MX points at a name that returned NXDOMAIN: "
                        + ", ".join(missing)
                        + ". Mail to this name may bounce. This is not proof of hijacking."
                    ),
                    recommendation=(
                        "If you operate the zone, point MX at a host that exists. "
                        "This tool does not speak SMTP."
                    ),
                    code="mx_host_nxdomain",
                )
            )
        if empty:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="MX target has no A/AAAA",
                    description=(
                        "MX points at a name with no A or AAAA: "
                        + ", ".join(empty)
                        + ". Delivery needs an address. This is not a compromise."
                    ),
                    recommendation=(
                        "Publish A/AAAA for the mail host, or change MX. "
                        "This tool does not open port 25."
                    ),
                    code="mx_host_no_address",
                )
            )
        return findings

    def _ns_hosts(self, observation: NsHostObservation) -> list[SecurityFinding]:
        if observation.status == "UNREADABLE":
            return [
                SecurityFinding(
                    severity="info",
                    title="NS hosts could not be read",
                    description=(
                        "The NS lookup timed out or failed. A timeout is not a missing "
                        "nameserver, and it is not a compromise."
                    ),
                    recommendation="Retry the NS lookup before treating delegation as unpublished.",
                    code="ns_unreadable",
                )
            ]
        findings: list[SecurityFinding] = []
        unread = [item.host for item in observation.checks if item.status == "UNREADABLE"]
        missing = [item.host for item in observation.checks if item.status == "NXDOMAIN"]
        empty = [item.host for item in observation.checks if item.status == "NO ADDRESS"]
        if unread:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="Some NS hosts could not be read",
                    description=(
                        "A/AAAA lookup timed out for: "
                        + ", ".join(unread)
                        + ". A timeout is not a missing address, and it is not a compromise."
                    ),
                    recommendation="Retry the host lookup before treating the NS target as unpublished.",
                    code="ns_host_unreadable",
                )
            )
        if missing:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="NS target does not exist",
                    description=(
                        "NS points at a name that returned NXDOMAIN: "
                        + ", ".join(missing)
                        + ". Resolvers may fail to reach this zone. This is not proof of hijacking, "
                        "and this tool does not test lame delegation."
                    ),
                    recommendation=(
                        "If you operate the zone, point NS at a host that exists. "
                        "This tool does not attempt AXFR."
                    ),
                    code="ns_host_nxdomain",
                )
            )
        if empty:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="NS target has no A/AAAA",
                    description=(
                        "NS points at a name with no A or AAAA: "
                        + ", ".join(empty)
                        + ". In-bailiwick names need glue at the parent; this recursive "
                        "lookup may still miss glue. This is not a compromise."
                    ),
                    recommendation=(
                        "Publish A/AAAA for the nameserver, or change NS. "
                        "This tool does not open port 53 to the NS."
                    ),
                    code="ns_host_no_address",
                )
            )
        return findings

    def _soa_ns(self, observation: SoaNsObservation) -> list[SecurityFinding]:
        if observation.status == "UNREADABLE":
            return [
                SecurityFinding(
                    severity="info",
                    title="SOA / NS could not be compared",
                    description=(
                        "SOA or NS lookup timed out or failed. A timeout is not a missing "
                        "primary, and it is not a compromise."
                    ),
                    recommendation="Retry the SOA/NS lookup before treating the primary as unpublished.",
                    code="soa_ns_unreadable",
                )
            ]
        if observation.status == "HIDDEN PRIMARY":
            primary = observation.mname or "(unknown)"
            return [
                SecurityFinding(
                    severity="info",
                    title="SOA primary is not in the NS set",
                    description=(
                        f"SOA mname is {primary}, which is not published as NS. "
                        "This can be a hidden master and is a common, valid design. "
                        "It is not proof of hijacking."
                    ),
                    recommendation=(
                        "If you operate the zone, this is expected when the primary "
                        "is hidden. This tool does not attempt AXFR."
                    ),
                    code="soa_hidden_primary",
                )
            ]
        if observation.status == "NO NS":
            return [
                SecurityFinding(
                    severity="info",
                    title="SOA without NS at this name",
                    description=(
                        "A SOA was returned but no NS records. On a subdomain the "
                        "delegation often lives at the parent. This is not a compromise."
                    ),
                    recommendation="Check NS at the parent if this name is not the zone apex.",
                    code="soa_without_ns",
                )
            ]
        return []

    def _cname_targets(self, observation: CnameTargetObservation) -> list[SecurityFinding]:
        if observation.status == "UNREADABLE":
            return [
                SecurityFinding(
                    severity="info",
                    title="CNAME targets could not be read",
                    description=(
                        "Following CNAME targets timed out or failed. A timeout is not a "
                        "dangling alias, and it is not a compromise."
                    ),
                    recommendation="Retry the CNAME lookup before treating the alias as unpublished.",
                    code="cname_target_unreadable",
                )
            ]
        findings: list[SecurityFinding] = []
        unread = [item.target for item in observation.checks if item.status == "UNREADABLE"]
        missing = [item.target for item in observation.checks if item.status == "NXDOMAIN"]
        empty = [item.target for item in observation.checks if item.status == "NO ADDRESS"]
        loops = [item.target for item in observation.checks if item.status == "LOOP"]
        deep = [item.target for item in observation.checks if item.status == "TOO DEEP"]
        if unread:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="Some CNAME targets could not be read",
                    description=(
                        "A/AAAA or CNAME lookup timed out for: "
                        + ", ".join(unread)
                        + ". A timeout is not a missing address, and it is not a takeover."
                    ),
                    recommendation="Retry the target lookup before treating the alias as dangling.",
                    code="cname_target_unreadable",
                )
            )
        if missing:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="CNAME target does not exist",
                    description=(
                        "CNAME points at a name that returned NXDOMAIN: "
                        + ", ".join(missing)
                        + ". That can be a leftover alias. It is not automatically an active takeover."
                    ),
                    recommendation=(
                        "If you operate the name, point the CNAME at a host that exists "
                        "or remove it. This tool does not fetch HTTP."
                    ),
                    code="cname_target_nxdomain",
                )
            )
        if empty:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="CNAME target has no A/AAAA",
                    description=(
                        "CNAME points at a name with no A or AAAA: "
                        + ", ".join(empty)
                        + ". That can be IPv6-only elsewhere, or a dangling alias. "
                        "It is not automatically an active takeover."
                    ),
                    recommendation="Resolve the target directly. This tool does not fetch HTTP.",
                    code="cname_target_no_address",
                )
            )
        if loops:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="CNAME loop",
                    description=(
                        "CNAME chain repeats a name: "
                        + ", ".join(loops)
                        + ". That is a configuration error, not proof of hijacking."
                    ),
                    recommendation="Break the loop so the alias ends at a name with A/AAAA.",
                    code="cname_target_loop",
                )
            )
        if deep:
            findings.append(
                SecurityFinding(
                    severity="info",
                    title="CNAME chain too long",
                    description=(
                        "CNAME chain exceeded 5 hops for: "
                        + ", ".join(deep)
                        + ". This tool stops there and does not fetch HTTP."
                    ),
                    recommendation="Shorten the alias chain so clients can resolve an address.",
                    code="cname_target_too_deep",
                )
            )
        return findings

    def _caa_observation(self, observation: CaaObservation) -> list[SecurityFinding]:
        if observation.status == "UNREADABLE":
            return [
                SecurityFinding(
                    severity="info",
                    title="CAA could not be read",
                    description=(
                        "CAA lookup timed out or failed. A timeout is not a missing "
                        "policy, and it is not a compromise."
                    ),
                    recommendation="Retry the CAA lookup before treating the name as unpublished.",
                    code="caa_unreadable",
                )
            ]
        if observation.status == "NOT DETECTED":
            return self._caa_missing()
        return []

    def _caa(self, lookup: CoreLookup) -> list[SecurityFinding]:
        if any(label == "CAA" for label, _ in lookup.errors):
            return []
        if lookup.caa:
            return []
        return self._caa_missing()

    def _caa_missing(self) -> list[SecurityFinding]:
        return [
            SecurityFinding(
                severity="info",
                title="CAA not published at this name",
                description=(
                    "No CAA records were returned. Certificate authorities may walk to "
                    "a parent name. Missing CAA here is not automatically unsafe."
                ),
                recommendation=(
                    "If you issue TLS certificates, CAA can restrict which CAs may issue. "
                    "Only add it if you intend that policy."
                ),
                code="caa_missing",
            )
        ]

    def _addresses(self, lookup: CoreLookup) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        for record in lookup.a + lookup.aaaa:
            scope = describe_ip_scope(record.value)
            if scope in {
                "private",
                "loopback",
                "link-local",
                "unspecified",
                "multicast",
                "reserved",
            }:
                findings.append(
                    SecurityFinding(
                        severity="medium",
                        title=f"{record.record_type} points to a {scope} address",
                        description=(
                            f"{record.value} is {scope} scope. On an internet-facing name "
                            "this is often a misconfiguration, not proof of a breach."
                        ),
                        recommendation="Confirm the name should not publish a public address, or fix the record.",
                        code="address_non_global",
                    )
                )
        return findings

    def _cname(self, lookup: CoreLookup) -> list[SecurityFinding]:
        if not lookup.cname:
            return []
        if any(label in {"A", "AAAA"} for label, _ in lookup.errors):
            return []
        if lookup.a or lookup.aaaa:
            return []
        return [
            SecurityFinding(
                severity="low",
                title="CNAME without A/AAAA in this view",
                description=(
                    "An alias exists but this resolver returned no A or AAAA. "
                    "That can be a dangling CNAME, an IPv6-only miss, or a timeout. "
                    "It is not automatically an active takeover."
                ),
                recommendation=(
                    "Resolve the CNAME target directly. If the target is gone, remove "
                    "the alias so someone else cannot claim it."
                ),
                code="cname_dangling",
            )
        ]

    def _txt_volume(self, lookup: CoreLookup) -> list[SecurityFinding]:
        if len(lookup.txt) <= _TXT_MANY:
            return []
        return [
            SecurityFinding(
                severity="info",
                title="Many TXT records",
                description=(
                    f"{len(lookup.txt)} TXT strings were returned. Volume alone is not "
                    "malicious; leftover verification tokens do add noise."
                ),
                recommendation="Review TXT records and remove unused verification strings.",
                code="txt_many",
            )
        ]
