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
from analyzer.dnssec import DnssecObservation
from analyzer.models import CoreLookup
from analyzer.mtasts import MtaStsObservation
from analyzer.records import describe_ip_scope
from analyzer.risk import RiskScore, score_risk
from analyzer.spf import SpfHop, SpfObservation
from analyzer.srv import SrvObservation
from analyzer.fcrdns import FcrdnsObservation
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
    """Build findings from lookup + DNSSEC/SPF/DMARC/DKIM/SRV/MTA-STS/TLS-RPT/BIMI/TLSA/SSHFP/FCrDNS observations."""

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
    ) -> SecurityReport:
        findings: list[SecurityFinding] = []
        findings.extend(self._dnssec(dnssec))
        findings.extend(self._spf(spf))
        findings.extend(self._dmarc(dmarc))
        findings.extend(self._dkim(dkim))
        findings.extend(self._srv(srv))
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
        findings.extend(self._caa(lookup))
        findings.extend(self._addresses(lookup))
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
            return []
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

    def _caa(self, lookup: CoreLookup) -> list[SecurityFinding]:
        if any(label == "CAA" for label, _ in lookup.errors):
            return []
        if lookup.caa:
            return []
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
