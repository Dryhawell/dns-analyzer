"""Serialize DNSAnalysisResult to JSON, CSV, or a self-contained HTML page.

The JSON schema is versioned (dns-analyzer.report.v1) so other tools can
consume reports without scraping CLI text. This is not a logging module.
HTML is for humans; every DNS value is escaped so a TXT string cannot run script.
"""

from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path

from analyzer.bimi import BimiObservation
from analyzer.fcrdns import FcrdnsCheck, FcrdnsObservation
from analyzer.mx import MxHostCheck, MxHostObservation
from analyzer.ns import NsHostCheck, NsHostObservation
from analyzer.cname import CnameTargetCheck, CnameTargetObservation
from analyzer.soa import SoaNsObservation
from analyzer.caa import CaaObservation, CaaProperty
from analyzer.cds import CdnskeyRecord, CdsObservation, CdsRecord
from analyzer.nsec import Nsec3ParamRecord, NsecObservation, NsecRecord
from analyzer.csync import CsyncObservation, CsyncRecord
from analyzer.zonemd import ZonemdObservation, ZonemdRecord
from analyzer.rrsig import RrsigObservation, RrsigRecord
from analyzer.sshfp import SshfpFingerprint, SshfpObservation
from analyzer.tlsa import TlsaObservation, TlsaAssociation
from analyzer.compare import ResolverComparison
from analyzer.dmarc import DmarcObservation
from analyzer.dkim import DkimObservation
from analyzer.dnssec import DnssecDelegation, DnssecKey, DnssecObservation
from analyzer.models import DNSRecord
from analyzer.mtasts import MtaStsObservation
from analyzer.result import DNSAnalysisResult
from analyzer.risk import RiskScore
from analyzer.security import SecurityFinding, SecurityReport
from analyzer.spf import SpfObservation
from analyzer.srv import SrvObservation
from analyzer.naptr import NaptrObservation, NaptrRewrite
from analyzer.uri import UriObservation, UriTarget
from analyzer.dname import DnameObservation, DnameTarget
from analyzer.ipseckey import IpseckeyObservation, IpseckeyRecord
from analyzer.smimea import SmimeaObservation, SmimeaAssociation
from analyzer.tlsrpt import TlsRptObservation
from analyzer.version import __version__

SCHEMA = "dns-analyzer.report.v1"


def record_to_dict(record: DNSRecord) -> dict[str, object]:
    return {
        "record_type": record.record_type,
        "name": record.name,
        "value": record.value,
        "ttl": record.ttl,
        "priority": record.priority,
        "details": [{"label": label, "value": value} for label, value in record.details],
    }


def result_to_dict(result: DNSAnalysisResult) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": SCHEMA,
        "tool_version": __version__,
        "target": result.target,
        "mode": result.mode,
        "scan_time": result.scan_time,
        "duration_ms": result.duration_ms,
        "cli": {
            "record_types": list(result.view_record_types)
            if result.view_record_types is not None
            else None,
            "security": result.view_security,
        },
        "records": [record_to_dict(item) for item in result.records],
        "errors": [
            {"section": section, "message": message} for section, message in result.errors
        ],
        "dnssec": _dnssec_dict(result.dnssec),
        "spf": _spf_dict(result.spf),
        "dmarc": _dmarc_dict(result.dmarc),
        "mta_sts": _mta_sts_dict(result.mta_sts),
        "tls_rpt": _tls_rpt_dict(result.tls_rpt),
        "bimi": _bimi_dict(result.bimi),
        "tlsa": _tlsa_dict(result.tlsa),
        "sshfp": _sshfp_dict(result.sshfp),
        "fcrdns": _fcrdns_dict(result.fcrdns),
        "mx_hosts": _mx_hosts_dict(result.mx_hosts),
        "ns_hosts": _ns_hosts_dict(result.ns_hosts),
        "cname_targets": _cname_targets_dict(result.cname_targets),
        "soa_ns": _soa_ns_dict(result.soa_ns),
        "caa": _caa_dict(result.caa),
        "cds": _cds_dict(result.cds),
        "nsec": _nsec_dict(result.nsec),
        "csync": _csync_dict(result.csync),
        "zonemd": _zonemd_dict(result.zonemd),
        "rrsig": _rrsig_dict(result.rrsig),
        "dkim": [_dkim_dict(item) for item in result.dkim] if result.dkim is not None else None,
        "srv": [_srv_dict(item) for item in result.srv] if result.srv is not None else None,
        "naptr": _naptr_dict(result.naptr) if result.naptr is not None else None,
        "uri": _uri_dict(result.uri) if result.uri is not None else None,
        "dname": _dname_dict(result.dname) if result.dname is not None else None,
        "ipseckey": _ipseckey_dict(result.ipseckey) if result.ipseckey is not None else None,
        "smimea": [_smimea_dict(item) for item in result.smimea] if result.smimea is not None else None,
        "security_analysis": _security_dict(result.security),
        "risk_score": _risk_dict(result.security.risk) if result.security else None,
    }
    if result.ptr_query is not None:
        payload["ptr_query"] = result.ptr_query
    if result.comparison is not None:
        payload["resolver_comparison"] = _comparison_dict(result.comparison)
    return payload


def dumps_json(result: DNSAnalysisResult) -> str:
    return json.dumps(result_to_dict(result), indent=2, ensure_ascii=False) + "\n"


def dumps_csv(result: DNSAnalysisResult) -> str:
    buffer = io.StringIO()
    _write_csv_rows(buffer, result)
    return buffer.getvalue()


def dumps_html(result: DNSAnalysisResult) -> str:
    """Standalone HTML report. No external CSS/JS; values are HTML-escaped."""
    return _html_document(result)


def write_json(path: Path, result: DNSAnalysisResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dumps_json(result), encoding="utf-8")


def write_csv(path: Path, result: DNSAnalysisResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        _write_csv_rows(handle, result)


def write_html(path: Path, result: DNSAnalysisResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dumps_html(result), encoding="utf-8")


def write_report(path: Path, result: DNSAnalysisResult, fmt: str) -> None:
    writers = {"json": write_json, "csv": write_csv, "html": write_html}
    writer = writers.get(fmt)
    if writer is None:
        raise ValueError(f"Unsupported export format: {fmt}")
    writer(path, result)


def format_from_suffix(path: Path) -> str | None:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix == ".csv":
        return "csv"
    if suffix == ".html":
        return "html"
    return None


def suggested_report_path(target: str, fmt: str, day: str) -> Path:
    """reports/<slug>_<YYYY-MM-DD>.json — used when documenting default names."""
    slug = "".join(ch if ch.isalnum() else "_" for ch in target.strip().lower())
    slug = slug.strip("_") or "scan"
    return Path("reports") / f"{slug}_{day}.{fmt}"


def _write_csv_rows(handle: io.TextIOBase, result: DNSAnalysisResult) -> None:
    writer = csv.writer(handle, lineterminator="\n")
    writer.writerow(["record_type", "name", "value", "ttl", "priority"])
    for record in result.records:
        writer.writerow(
            [
                record.record_type,
                record.name,
                record.value,
                record.ttl,
                "" if record.priority is None else record.priority,
            ]
        )


def _dnssec_dict(observation: DnssecObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "dnskey_found": observation.dnskey_found,
        "ds_found": observation.ds_found,
        "ad_flag": observation.ad_flag,
        "note": observation.note,
        "error": observation.error,
        "keys": [_dnssec_key_dict(item) for item in observation.keys],
        "delegations": [_dnssec_ds_dict(item) for item in observation.delegations],
        "keys_truncated": observation.keys_truncated,
        "delegations_truncated": observation.delegations_truncated,
    }


def _dnssec_key_dict(item: DnssecKey) -> dict[str, object]:
    return {
        "flags": item.flags,
        "protocol": item.protocol,
        "algorithm": item.algorithm,
        "algorithm_meaning": item.algorithm_meaning,
        "role": item.role,
        "zone_key": item.zone_key,
        "secure_entry_point": item.secure_entry_point,
        "key_tag": item.key_tag,
    }


def _dnssec_ds_dict(item: DnssecDelegation) -> dict[str, object]:
    return {
        "key_tag": item.key_tag,
        "algorithm": item.algorithm,
        "algorithm_meaning": item.algorithm_meaning,
        "digest_type": item.digest_type,
        "digest_meaning": item.digest_meaning,
    }


def _spf_dict(observation: SpfObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "policies": list(observation.policies),
        "all_term": observation.all_term,
        "all_meaning": observation.all_meaning,
        "multiple_records": observation.multiple_records,
        "note": observation.note,
        "error": observation.error,
        "hops": [
            {
                "kind": hop.kind,
                "domain": hop.domain,
                "status": hop.status,
                "policy": hop.policy,
                "all_term": hop.all_term,
                "all_meaning": hop.all_meaning,
                "nested_includes": list(hop.nested_includes),
                "error": hop.error,
            }
            for hop in observation.hops
        ],
    }


def _dmarc_dict(observation: DmarcObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "record": observation.record,
        "policy": observation.policy,
        "policy_meaning": observation.policy_meaning,
        "subdomain_policy": observation.subdomain_policy,
        "pct": observation.pct,
        "rua": observation.rua,
        "multiple_records": observation.multiple_records,
        "note": observation.note,
        "error": observation.error,
    }


def _mta_sts_dict(observation: MtaStsObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "policy_host": observation.policy_host,
        "record": observation.record,
        "id": observation.policy_id,
        "multiple_records": observation.multiple_records,
        "note": observation.note,
        "error": observation.error,
    }


def _tls_rpt_dict(observation: TlsRptObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "record": observation.record,
        "rua": observation.rua,
        "multiple_records": observation.multiple_records,
        "note": observation.note,
        "error": observation.error,
    }


def _bimi_dict(observation: BimiObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "selector": observation.selector,
        "query_name": observation.query_name,
        "record": observation.record,
        "location": observation.location,
        "authority": observation.authority,
        "multiple_records": observation.multiple_records,
        "note": observation.note,
        "error": observation.error,
    }


def _tlsa_association_dict(item: TlsaAssociation) -> dict[str, object]:
    return {
        "usage": item.usage,
        "selector": item.selector,
        "matching_type": item.matching_type,
        "association": item.association,
        "association_truncated": item.association_truncated,
        "usage_meaning": item.usage_meaning,
        "selector_meaning": item.selector_meaning,
        "matching_meaning": item.matching_meaning,
    }


def _tlsa_dict(observation: TlsaObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "port": observation.port,
        "protocol": observation.protocol,
        "records": [_tlsa_association_dict(item) for item in observation.associations],
        "note": observation.note,
        "error": observation.error,
    }


def _sshfp_fingerprint_dict(item: SshfpFingerprint) -> dict[str, object]:
    return {
        "algorithm": item.algorithm,
        "fingerprint_type": item.fingerprint_type,
        "fingerprint": item.fingerprint,
        "fingerprint_truncated": item.fingerprint_truncated,
        "algorithm_meaning": item.algorithm_meaning,
        "fingerprint_type_meaning": item.fingerprint_type_meaning,
    }


def _sshfp_dict(observation: SshfpObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "records": [_sshfp_fingerprint_dict(item) for item in observation.fingerprints],
        "note": observation.note,
        "error": observation.error,
    }


def _fcrdns_check_dict(item: FcrdnsCheck) -> dict[str, object]:
    return {
        "ip": item.ip,
        "ptr_query": item.ptr_query,
        "ptr_names": list(item.ptr_names),
        "forward_ips": list(item.forward_ips),
        "status": item.status,
        "error": item.error,
    }


def _fcrdns_dict(observation: FcrdnsObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "checks": [_fcrdns_check_dict(item) for item in observation.checks],
        "truncated": observation.truncated,
        "note": observation.note,
    }


def _mx_host_check_dict(item: MxHostCheck) -> dict[str, object]:
    return {
        "host": item.host,
        "preference": item.preference,
        "ipv4": list(item.ipv4),
        "ipv6": list(item.ipv6),
        "status": item.status,
        "error": item.error,
    }


def _mx_hosts_dict(observation: MxHostObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "checks": [_mx_host_check_dict(item) for item in observation.checks],
        "truncated": observation.truncated,
        "note": observation.note,
        "error": observation.error,
    }


def _ns_host_check_dict(item: NsHostCheck) -> dict[str, object]:
    return {
        "host": item.host,
        "in_bailiwick": item.in_bailiwick,
        "ipv4": list(item.ipv4),
        "ipv6": list(item.ipv6),
        "status": item.status,
        "error": item.error,
    }


def _ns_hosts_dict(observation: NsHostObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "checks": [_ns_host_check_dict(item) for item in observation.checks],
        "truncated": observation.truncated,
        "note": observation.note,
        "error": observation.error,
    }


def _cname_target_check_dict(item: CnameTargetCheck) -> dict[str, object]:
    return {
        "target": item.target,
        "chain": list(item.chain),
        "ipv4": list(item.ipv4),
        "ipv6": list(item.ipv6),
        "status": item.status,
        "error": item.error,
    }


def _cname_targets_dict(observation: CnameTargetObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "checks": [_cname_target_check_dict(item) for item in observation.checks],
        "truncated": observation.truncated,
        "note": observation.note,
        "error": observation.error,
    }


def _soa_ns_dict(observation: SoaNsObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "mname": observation.mname,
        "serial": observation.serial,
        "ns_hosts": list(observation.ns_hosts),
        "note": observation.note,
        "error": observation.error,
    }


def _caa_property_dict(item: CaaProperty) -> dict[str, object]:
    return {
        "flags": item.flags,
        "issuer_critical": item.issuer_critical,
        "tag": item.tag,
        "tag_meaning": item.tag_meaning,
        "value": item.value,
    }


def _caa_dict(observation: CaaObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "properties": [_caa_property_dict(item) for item in observation.properties],
        "issue": list(observation.issue),
        "issuewild": list(observation.issuewild),
        "iodef": list(observation.iodef),
        "truncated": observation.truncated,
        "note": observation.note,
        "error": observation.error,
    }


def _cds_dict(observation: CdsObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "cds_found": observation.cds_found,
        "cdnskey_found": observation.cdnskey_found,
        "cds": [_cds_record_dict(item) for item in observation.cds],
        "cdnskey": [_cdnskey_record_dict(item) for item in observation.cdnskey],
        "cds_truncated": observation.cds_truncated,
        "cdnskey_truncated": observation.cdnskey_truncated,
        "note": observation.note,
        "error": observation.error,
    }


def _cds_record_dict(item: CdsRecord) -> dict[str, object]:
    return {
        "key_tag": item.key_tag,
        "algorithm": item.algorithm,
        "algorithm_meaning": item.algorithm_meaning,
        "digest_type": item.digest_type,
        "digest_meaning": item.digest_meaning,
    }


def _cdnskey_record_dict(item: CdnskeyRecord) -> dict[str, object]:
    return {
        "flags": item.flags,
        "protocol": item.protocol,
        "algorithm": item.algorithm,
        "algorithm_meaning": item.algorithm_meaning,
        "role": item.role,
        "zone_key": item.zone_key,
        "secure_entry_point": item.secure_entry_point,
        "key_tag": item.key_tag,
    }


def _nsec_dict(observation: NsecObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "nsec_found": observation.nsec_found,
        "nsec3param_found": observation.nsec3param_found,
        "nsec": [_nsec_record_dict(item) for item in observation.nsec],
        "nsec3param": [_nsec3param_dict(item) for item in observation.nsec3param],
        "nsec_truncated": observation.nsec_truncated,
        "nsec3param_truncated": observation.nsec3param_truncated,
        "note": observation.note,
        "error": observation.error,
    }


def _nsec_record_dict(item: NsecRecord) -> dict[str, object]:
    return {
        "next_name": item.next_name,
        "types": list(item.types),
        "types_truncated": item.types_truncated,
    }


def _nsec3param_dict(item: Nsec3ParamRecord) -> dict[str, object]:
    return {
        "algorithm": item.algorithm,
        "algorithm_meaning": item.algorithm_meaning,
        "flags": item.flags,
        "opt_out": item.opt_out,
        "iterations": item.iterations,
        "salt_length": item.salt_length,
        "iterations_note": item.iterations_note,
    }


def _csync_dict(observation: CsyncObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "csync": [_csync_record_dict(item) for item in observation.csync],
        "truncated": observation.truncated,
        "note": observation.note,
        "error": observation.error,
    }


def _csync_record_dict(item: CsyncRecord) -> dict[str, object]:
    return {
        "serial": item.serial,
        "flags": item.flags,
        "immediate": item.immediate,
        "soa_minimum": item.soa_minimum,
        "types": list(item.types),
        "types_truncated": item.types_truncated,
    }


def _zonemd_dict(observation: ZonemdObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "zonemd": [_zonemd_record_dict(item) for item in observation.zonemd],
        "truncated": observation.truncated,
        "note": observation.note,
        "error": observation.error,
    }


def _zonemd_record_dict(item: ZonemdRecord) -> dict[str, object]:
    return {
        "serial": item.serial,
        "scheme": item.scheme,
        "scheme_meaning": item.scheme_meaning,
        "hash_algorithm": item.hash_algorithm,
        "hash_meaning": item.hash_meaning,
        "digest_length": item.digest_length,
    }


def _rrsig_dict(observation: RrsigObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "rrsig": [_rrsig_record_dict(item) for item in observation.rrsig],
        "truncated": observation.truncated,
        "note": observation.note,
        "error": observation.error,
    }


def _rrsig_record_dict(item: RrsigRecord) -> dict[str, object]:
    return {
        "type_covered": item.type_covered,
        "type_covered_name": item.type_covered_name,
        "algorithm": item.algorithm,
        "algorithm_meaning": item.algorithm_meaning,
        "labels": item.labels,
        "original_ttl": item.original_ttl,
        "inception": item.inception,
        "expiration": item.expiration,
        "inception_utc": item.inception_utc,
        "expiration_utc": item.expiration_utc,
        "key_tag": item.key_tag,
        "signer": item.signer,
        "signature_length": item.signature_length,
    }


def _dkim_dict(observation: DkimObservation) -> dict[str, object]:
    return {
        "status": observation.status,
        "selector": observation.selector,
        "query_name": observation.query_name,
        "record": observation.record,
        "key_type": observation.key_type,
        "key_chars": observation.key_chars,
        "key_present": observation.key_present,
        "revoked": observation.revoked,
        "multiple_records": observation.multiple_records,
        "note": observation.note,
        "error": observation.error,
    }


def _srv_dict(observation: SrvObservation) -> dict[str, object]:
    return {
        "status": observation.status,
        "service": observation.service,
        "protocol": observation.protocol,
        "query_name": observation.query_name,
        "records": [record_to_dict(item) for item in observation.records],
        "note": observation.note,
        "error": observation.error,
    }


def _naptr_dict(observation: NaptrObservation) -> dict[str, object]:
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "rewrites": [_naptr_rewrite_dict(item) for item in observation.rewrites],
        "truncated": observation.truncated,
        "note": observation.note,
        "error": observation.error,
    }


def _naptr_rewrite_dict(item: NaptrRewrite) -> dict[str, object]:
    return {
        "order": item.order,
        "preference": item.preference,
        "flags": item.flags,
        "flags_meaning": item.flags_meaning,
        "services": item.services,
        "regexp": item.regexp,
        "replacement": item.replacement,
    }


def _uri_dict(observation: UriObservation) -> dict[str, object]:
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "uris": [_uri_target_dict(item) for item in observation.uris],
        "truncated": observation.truncated,
        "note": observation.note,
        "error": observation.error,
    }


def _uri_target_dict(item: UriTarget) -> dict[str, object]:
    return {
        "priority": item.priority,
        "weight": item.weight,
        "target": item.target,
        "scheme": item.scheme,
        "scheme_meaning": item.scheme_meaning,
    }


def _dname_dict(observation: DnameObservation) -> dict[str, object]:
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "dnames": [_dname_target_dict(item) for item in observation.dnames],
        "truncated": observation.truncated,
        "note": observation.note,
        "error": observation.error,
    }


def _dname_target_dict(item: DnameTarget) -> dict[str, object]:
    return {"target": item.target}


def _ipseckey_dict(observation: IpseckeyObservation) -> dict[str, object]:
    return {
        "status": observation.status,
        "query_name": observation.query_name,
        "ipseckeys": [_ipseckey_record_dict(item) for item in observation.ipseckeys],
        "truncated": observation.truncated,
        "note": observation.note,
        "error": observation.error,
    }


def _smimea_dict(observation: SmimeaObservation) -> dict[str, object]:
    return {
        "status": observation.status,
        "local_part": observation.local_part,
        "query_name": observation.query_name,
        "associations": [_smimea_association_dict(item) for item in observation.associations],
        "truncated": observation.truncated,
        "note": observation.note,
        "error": observation.error,
    }


def _smimea_association_dict(item: SmimeaAssociation) -> dict[str, object]:
    return {
        "usage": item.usage,
        "selector": item.selector,
        "matching_type": item.matching_type,
        "association_length": item.association_length,
        "usage_meaning": item.usage_meaning,
        "selector_meaning": item.selector_meaning,
        "matching_meaning": item.matching_meaning,
    }


def _ipseckey_record_dict(item: IpseckeyRecord) -> dict[str, object]:
    return {
        "precedence": item.precedence,
        "gateway_type": item.gateway_type,
        "gateway_type_meaning": item.gateway_type_meaning,
        "algorithm": item.algorithm,
        "algorithm_meaning": item.algorithm_meaning,
        "gateway": item.gateway,
        "key_length": item.key_length,
    }


def _security_dict(report: SecurityReport | None) -> dict[str, object] | None:
    if report is None:
        return None
    return {
        "disclaimer": report.disclaimer,
        "highest_severity": report.highest_severity,
        "findings": [_finding_dict(item) for item in report.findings],
    }


def _finding_dict(finding: SecurityFinding) -> dict[str, object]:
    return {
        "code": finding.code,
        "severity": finding.severity,
        "title": finding.title,
        "description": finding.description,
        "recommendation": finding.recommendation,
    }


def _risk_dict(risk: RiskScore) -> dict[str, object]:
    return {
        "value": risk.value,
        "band": risk.band,
        "raw_total": risk.raw_total,
        "capped": risk.capped,
        "note": risk.note,
        "contributions": [
            {"code": item.code, "label": item.label, "points": item.points}
            for item in risk.contributions
        ],
    }


def _comparison_dict(comparison: ResolverComparison) -> dict[str, object]:
    return {
        "primary": comparison.primary,
        "status": comparison.status,
        "inconsistent_types": list(comparison.inconsistent_types),
        "note": comparison.note,
        "resolvers": [
            {
                "name": item.name,
                "nameservers": list(item.nameservers),
                "records": {label: list(values) for label, values in item.answers.items()},
                "error": item.error,
            }
            for item in comparison.snapshots
        ],
    }


def _e(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _html_document(result: DNSAnalysisResult) -> str:
    title = f"DNS Analyzer — {_e(result.target)}"
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{title}</title>",
        "<style>",
        _HTML_CSS,
        "</style>",
        "</head>",
        "<body>",
        "<header>",
        "<p class=\"brand\">DNS Analyzer</p>",
        f"<h1>{_e(result.target)}</h1>",
        "<p class=\"meta\">",
        f"mode {_e(result.mode)} · {_e(result.scan_time)} · {result.duration_ms} ms · ",
        f"tool {_e(__version__)}",
        "</p>",
        "</header>",
        "<aside class=\"disclaimer\">",
        "This is not a vulnerability scanner. Missing DNSSEC, SPF, DMARC, or CAA ",
        "is an observation, not proof of compromise.",
        "</aside>",
    ]
    if result.ptr_query:
        parts.append(f"<p>PTR query: <code>{_e(result.ptr_query)}</code></p>")
    parts.extend(_html_records(result))
    parts.extend(_html_errors(result))
    if result.dnssec is not None:
        parts.extend(_html_dnssec(result.dnssec))
    if result.cds is not None:
        parts.extend(_html_cds(result.cds))
    if result.nsec is not None:
        parts.extend(_html_nsec(result.nsec))
    if result.csync is not None:
        parts.extend(_html_csync(result.csync))
    if result.zonemd is not None:
        parts.extend(_html_zonemd(result.zonemd))
    if result.rrsig is not None:
        parts.extend(_html_rrsig(result.rrsig))
    if result.spf is not None:
        parts.extend(_html_spf(result.spf))
    if result.dmarc is not None:
        parts.extend(_html_dmarc(result.dmarc))
    if result.mta_sts is not None:
        parts.extend(_html_mta_sts(result.mta_sts))
    if result.tls_rpt is not None:
        parts.extend(_html_tls_rpt(result.tls_rpt))
    if result.bimi is not None:
        parts.extend(_html_bimi(result.bimi))
    if result.tlsa is not None:
        parts.extend(_html_tlsa(result.tlsa))
    if result.sshfp is not None:
        parts.extend(_html_sshfp(result.sshfp))
    if result.fcrdns is not None:
        parts.extend(_html_fcrdns(result.fcrdns))
    if result.mx_hosts is not None:
        parts.extend(_html_mx_hosts(result.mx_hosts))
    if result.ns_hosts is not None:
        parts.extend(_html_ns_hosts(result.ns_hosts))
    if result.cname_targets is not None:
        parts.extend(_html_cname_targets(result.cname_targets))
    if result.soa_ns is not None:
        parts.extend(_html_soa_ns(result.soa_ns))
    if result.caa is not None:
        parts.extend(_html_caa(result.caa))
    if result.dkim:
        for item in result.dkim:
            parts.extend(_html_dkim(item))
    if result.srv:
        for item in result.srv:
            parts.extend(_html_srv(item))
    if result.naptr is not None:
        parts.extend(_html_naptr(result.naptr))
    if result.uri is not None:
        parts.extend(_html_uri(result.uri))
    if result.dname is not None:
        parts.extend(_html_dname(result.dname))
    if result.ipseckey is not None:
        parts.extend(_html_ipseckey(result.ipseckey))
    if result.smimea:
        for item in result.smimea:
            parts.extend(_html_smimea(item))
    if result.security is not None:
        parts.extend(_html_security(result.security))
    if result.comparison is not None:
        parts.extend(_html_comparison(result.comparison))
    parts.extend(["</body>", "</html>", ""])
    return "\n".join(parts)


_HTML_CSS = """
:root { font-family: Segoe UI, system-ui, sans-serif; color: #1a1a1a; }
body { max-width: 52rem; margin: 1.5rem auto; padding: 0 1rem 3rem; line-height: 1.45; }
.brand { text-transform: uppercase; letter-spacing: .08em; font-size: .75rem; color: #555; }
h1 { margin: .2rem 0 .4rem; font-size: 1.6rem; }
.meta, .note { color: #444; font-size: .9rem; }
.disclaimer { background: #fff6e5; border: 1px solid #e6c98a; padding: .75rem 1rem; margin: 1rem 0 1.5rem; }
h2 { font-size: 1.05rem; margin: 1.6rem 0 .6rem; border-bottom: 1px solid #ddd; padding-bottom: .25rem; }
table { width: 100%; border-collapse: collapse; font-size: .9rem; }
th, td { text-align: left; padding: .35rem .5rem; border-bottom: 1px solid #eee; vertical-align: top; }
th { color: #555; font-weight: 600; }
code { font-size: .85em; word-break: break-all; }
.finding { border: 1px solid #ddd; padding: .7rem 1rem; margin: .6rem 0; }
.sev-info { border-left: 4px solid #6b7280; }
.sev-low { border-left: 4px solid #2563eb; }
.sev-medium { border-left: 4px solid #d97706; }
.sev-high { border-left: 4px solid #dc2626; }
.band { font-weight: 700; }
@media print {
  body { margin: 0; max-width: none; }
  .disclaimer, .finding { break-inside: avoid; }
}
"""


def _html_records(result: DNSAnalysisResult) -> list[str]:
    if not result.records:
        return ["<h2>Records</h2>", "<p>No records in this view.</p>"]
    rows = [
        "<h2>Records</h2>",
        "<table>",
        "<thead><tr><th>Type</th><th>Name</th><th>Value</th><th>TTL</th><th>Priority</th></tr></thead>",
        "<tbody>",
    ]
    for record in result.records:
        priority = "" if record.priority is None else str(record.priority)
        rows.append(
            "<tr>"
            f"<td>{_e(record.record_type)}</td>"
            f"<td>{_e(record.name)}</td>"
            f"<td><code>{_e(record.value)}</code></td>"
            f"<td>{record.ttl}</td>"
            f"<td>{_e(priority)}</td>"
            "</tr>"
        )
    rows.extend(["</tbody>", "</table>"])
    return rows


def _html_errors(result: DNSAnalysisResult) -> list[str]:
    if not result.errors:
        return []
    rows = ["<h2>Lookup notes</h2>", "<ul>"]
    for section, message in result.errors:
        rows.append(f"<li>{_e(section)}: {_e(message)}</li>")
    rows.append("</ul>")
    return rows


def _html_dnssec(observation: DnssecObservation) -> list[str]:
    parts = [
        "<h2>DNSSEC</h2>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
        "<ul>",
        f"<li>DNSKEY: {'found' if observation.dnskey_found else 'not found'}</li>",
        f"<li>DS: {'found' if observation.ds_found else 'not found'}</li>",
        f"<li>AD flag: {'set' if observation.ad_flag else 'not set'} (this resolver)</li>",
        "</ul>",
    ]
    if observation.keys:
        parts.append("<p>Keys:</p>")
        parts.append("<ul>")
        for key in observation.keys:
            tag = f", key tag {key.key_tag}" if key.key_tag is not None else ""
            parts.append(
                "<li>"
                f"{key.flags} {key.protocol} {key.algorithm} "
                f"({_e(key.role)}, {_e(key.algorithm_meaning)}{_e(tag)})"
                "</li>"
            )
        parts.append("</ul>")
        if observation.keys_truncated:
            parts.append(
                '<p class="note">more than 8 DNSKEY records; extras were not listed.</p>'
            )
    if observation.delegations:
        parts.append("<p>Delegations (DS):</p>")
        parts.append("<ul>")
        for item in observation.delegations:
            parts.append(
                "<li>"
                f"{item.key_tag} {item.algorithm} {item.digest_type} "
                f"({_e(item.algorithm_meaning)}, {_e(item.digest_meaning)})"
                "</li>"
            )
        parts.append("</ul>")
        if observation.delegations_truncated:
            parts.append(
                '<p class="note">more than 8 DS records; extras were not listed.</p>'
            )
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    return parts


def _html_cds(observation: CdsObservation) -> list[str]:
    parts = [
        "<h2>CDS / CDNSKEY</h2>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
        "<ul>",
        f"<li>CDS: {'found' if observation.cds_found else 'not found'}</li>",
        f"<li>CDNSKEY: {'found' if observation.cdnskey_found else 'not found'}</li>",
        "</ul>",
    ]
    if observation.status == "NOT DETECTED":
        parts.append("<p>No CDS or CDNSKEY records at this name.</p>")
    if observation.cds:
        parts.append("<p>CDS:</p>")
        parts.append("<ul>")
        for item in observation.cds:
            parts.append(
                "<li>"
                f"{item.key_tag} {item.algorithm} {item.digest_type} "
                f"({_e(item.algorithm_meaning)}, {_e(item.digest_meaning)})"
                "</li>"
            )
        parts.append("</ul>")
        if observation.cds_truncated:
            parts.append(
                '<p class="note">more than 8 CDS records; extras were not listed.</p>'
            )
    if observation.cdnskey:
        parts.append("<p>CDNSKEY:</p>")
        parts.append("<ul>")
        for key in observation.cdnskey:
            tag = f", key tag {key.key_tag}" if key.key_tag is not None else ""
            parts.append(
                "<li>"
                f"{key.flags} {key.protocol} {key.algorithm} "
                f"({_e(key.role)}, {_e(key.algorithm_meaning)}{_e(tag)})"
                "</li>"
            )
        parts.append("</ul>")
        if observation.cdnskey_truncated:
            parts.append(
                '<p class="note">more than 8 CDNSKEY records; extras were not listed.</p>'
            )
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_nsec(observation: NsecObservation) -> list[str]:
    parts = [
        "<h2>NSEC / NSEC3PARAM</h2>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
        "<ul>",
        f"<li>NSEC3PARAM: {'found' if observation.nsec3param_found else 'not found'}</li>",
        f"<li>NSEC: {'found' if observation.nsec_found else 'not found'}</li>",
        "</ul>",
    ]
    if observation.status == "NOT DETECTED":
        parts.append("<p>No NSEC or NSEC3PARAM records at this name.</p>")
    if observation.nsec3param:
        parts.append("<p>NSEC3PARAM:</p>")
        parts.append("<ul>")
        for item in observation.nsec3param:
            opt = ", opt-out" if item.opt_out else ""
            parts.append(
                "<li>"
                f"{item.algorithm} {item.flags} {item.iterations} "
                f"({_e(item.algorithm_meaning)}, salt length {item.salt_length}{_e(opt)})"
                f" — {_e(item.iterations_note)}"
                "</li>"
            )
        parts.append("</ul>")
        if observation.nsec3param_truncated:
            parts.append(
                '<p class="note">more than 8 NSEC3PARAM records; extras were not listed.</p>'
            )
    if observation.nsec:
        parts.append("<p>NSEC (this name only; next name is not queried):</p>")
        parts.append("<ul>")
        for item in observation.nsec:
            types = " ".join(item.types) if item.types else "(types not listed)"
            extra = " …" if item.types_truncated else ""
            parts.append(
                "<li>"
                f"next <code>{_e(item.next_name)}</code> {_e(types)}{_e(extra)}"
                "</li>"
            )
        parts.append("</ul>")
        if observation.nsec_truncated:
            parts.append(
                '<p class="note">more than 8 NSEC records; extras were not listed.</p>'
            )
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_csync(observation: CsyncObservation) -> list[str]:
    parts = [
        "<h2>CSYNC</h2>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.status == "NOT DETECTED":
        parts.append("<p>No CSYNC records at this name.</p>")
    if observation.csync:
        parts.append("<p>CSYNC:</p>")
        parts.append("<ul>")
        for item in observation.csync:
            flags = []
            if item.immediate:
                flags.append("immediate")
            if item.soa_minimum:
                flags.append("soaminimum")
            flag_text = ", ".join(flags) if flags else "no flags"
            types = " ".join(item.types) if item.types else "(types not listed)"
            extra = " …" if item.types_truncated else ""
            parts.append(
                "<li>"
                f"serial {item.serial} flags {item.flags} ({_e(flag_text)})"
                f" types {_e(types)}{_e(extra)}"
                "</li>"
            )
        parts.append("</ul>")
        if observation.truncated:
            parts.append(
                '<p class="note">more than 8 CSYNC records; extras were not listed.</p>'
            )
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_zonemd(observation: ZonemdObservation) -> list[str]:
    parts = [
        "<h2>ZONEMD</h2>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.status == "NOT DETECTED":
        parts.append("<p>No ZONEMD records at this name.</p>")
    if observation.zonemd:
        parts.append("<p>ZONEMD:</p>")
        parts.append("<ul>")
        for item in observation.zonemd:
            parts.append(
                "<li>"
                f"serial {item.serial} scheme {item.scheme} "
                f"hash {item.hash_algorithm} "
                f"({_e(item.scheme_meaning)}, {_e(item.hash_meaning)}, "
                f"digest length {item.digest_length})"
                "</li>"
            )
        parts.append("</ul>")
        if observation.truncated:
            parts.append(
                '<p class="note">more than 8 ZONEMD records; extras were not listed.</p>'
            )
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_rrsig(observation: RrsigObservation) -> list[str]:
    parts = [
        "<h2>RRSIG</h2>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.status == "NOT DETECTED":
        parts.append("<p>No RRSIG records at this name.</p>")
    if observation.rrsig:
        parts.append("<p>RRSIG:</p>")
        parts.append("<ul>")
        for item in observation.rrsig:
            parts.append(
                "<li>"
                f"{_e(item.type_covered_name)} alg {item.algorithm} "
                f"({_e(item.algorithm_meaning)}) labels {item.labels} "
                f"origttl {item.original_ttl} "
                f"{_e(item.inception_utc)} → {_e(item.expiration_utc)} "
                f"key {item.key_tag} signer {_e(item.signer)} "
                f"(sig length {item.signature_length})"
                "</li>"
            )
        parts.append("</ul>")
        if observation.truncated:
            parts.append(
                '<p class="note">more than 8 RRSIG records; extras were not listed.</p>'
            )
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_spf(observation: SpfObservation) -> list[str]:
    parts = ["<h2>SPF</h2>", f"<p>Status: <strong>{_e(observation.status)}</strong></p>"]
    if observation.policies:
        parts.append(f"<p><code>{_e(observation.policies[0])}</code></p>")
        if observation.all_term:
            parts.append(
                f"<p>all: {_e(observation.all_term)} — {_e(observation.all_meaning)}</p>"
            )
        if observation.hops:
            parts.append("<p>Includes (one hop; not a full SPF evaluation)</p><ul>")
            for hop in observation.hops:
                if hop.policy:
                    parts.append(
                        f"<li>{_e(hop.kind)} <code>{_e(hop.domain)}</code>: "
                        f"<code>{_e(hop.policy)}</code></li>"
                    )
                else:
                    extra = f" — {_e(hop.error)}" if hop.error else ""
                    parts.append(
                        f"<li>{_e(hop.kind)} <code>{_e(hop.domain)}</code>: "
                        f"{_e(hop.status)}{extra}</li>"
                    )
            parts.append("</ul>")
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_dmarc(observation: DmarcObservation) -> list[str]:
    parts = [
        "<h2>DMARC</h2>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.record:
        parts.append(f"<p><code>{_e(observation.record)}</code></p>")
        if observation.policy:
            parts.append(f"<p>p={_e(observation.policy)} {_e(observation.policy_meaning)}</p>")
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_mta_sts(observation: MtaStsObservation) -> list[str]:
    parts = [
        "<h2>MTA-STS</h2>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Policy host: <code>{_e(observation.policy_host)}</code> (HTTPS file not fetched)</p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.record:
        parts.append(f"<p><code>{_e(observation.record)}</code></p>")
        if observation.policy_id:
            parts.append(f"<p>id={_e(observation.policy_id)}</p>")
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_tls_rpt(observation: TlsRptObservation) -> list[str]:
    parts = [
        "<h2>TLS-RPT</h2>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.record:
        parts.append(f"<p><code>{_e(observation.record)}</code></p>")
        if observation.rua:
            parts.append(f"<p>rua={_e(observation.rua)}</p>")
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_bimi(observation: BimiObservation) -> list[str]:
    parts = [
        "<h2>BIMI</h2>",
        f"<p>Selector: <code>{_e(observation.selector)}</code></p>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.record:
        parts.append(f"<p><code>{_e(observation.record)}</code></p>")
        if observation.location:
            parts.append(f"<p>l={_e(observation.location)} (URL not fetched)</p>")
        if observation.authority:
            parts.append(f"<p>a={_e(observation.authority)} (URL not fetched)</p>")
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_tlsa(observation: TlsaObservation) -> list[str]:
    parts = [
        "<h2>DANE / TLSA</h2>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Port/protocol: {observation.port}/{_e(observation.protocol)} (HTTPS)</p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    for item in observation.associations:
        parts.append(
            f"<p><code>{item.usage} {item.selector} {item.matching_type} "
            f"{_e(item.association)}</code></p>"
        )
        parts.append(f"<p>usage: {_e(item.usage_meaning)}</p>")
        parts.append(f"<p>selector: {_e(item.selector_meaning)}</p>")
        parts.append(f"<p>matching: {_e(item.matching_meaning)}</p>")
        if item.association_truncated:
            parts.append("<p class=\"note\">association hex truncated (full certificate not dumped)</p>")
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_sshfp(observation: SshfpObservation) -> list[str]:
    parts = [
        "<h2>SSHFP</h2>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    for item in observation.fingerprints:
        parts.append(
            f"<p><code>{item.algorithm} {item.fingerprint_type} "
            f"{_e(item.fingerprint)}</code></p>"
        )
        parts.append(f"<p>algorithm: {_e(item.algorithm_meaning)}</p>")
        parts.append(f"<p>fingerprint type: {_e(item.fingerprint_type_meaning)}</p>")
        if item.fingerprint_truncated:
            parts.append("<p class=\"note\">fingerprint hex truncated</p>")
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_fcrdns(observation: FcrdnsObservation) -> list[str]:
    parts = ["<h2>FCrDNS</h2>"]
    if not observation.checks:
        parts.append("<p>No A/AAAA addresses to check.</p>")
    for item in observation.checks:
        parts.append(f"<p><code>{_e(item.ip)}</code> — <strong>{_e(item.status)}</strong></p>")
        parts.append(f"<p>PTR query: <code>{_e(item.ptr_query)}</code></p>")
        if item.ptr_names:
            parts.append(f"<p>PTR: <code>{_e(', '.join(item.ptr_names))}</code></p>")
        if item.forward_ips:
            parts.append(f"<p>Forward: <code>{_e(', '.join(item.forward_ips))}</code></p>")
        if item.error:
            parts.append(f"<p class=\"note\">{_e(item.error)}</p>")
    if observation.truncated:
        parts.append("<p class=\"note\">More than 8 addresses; extra A/AAAA were not checked.</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_mx_hosts(observation: MxHostObservation) -> list[str]:
    parts = [
        "<h2>MX hosts</h2>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.status == "NOT DETECTED":
        parts.append("<p>No MX records at this name.</p>")
    for item in observation.checks:
        pref = (
            f" preference {item.preference}" if item.preference is not None else ""
        )
        parts.append(
            f"<p><code>{_e(item.host)}</code>{_e(pref)} — "
            f"<strong>{_e(item.status)}</strong></p>"
        )
        if item.ipv4:
            parts.append(f"<p>A: <code>{_e(', '.join(item.ipv4))}</code></p>")
        if item.ipv6:
            parts.append(f"<p>AAAA: <code>{_e(', '.join(item.ipv6))}</code></p>")
        if item.error:
            parts.append(f"<p class=\"note\">{_e(item.error)}</p>")
    if observation.truncated:
        parts.append("<p class=\"note\">More than 8 MX hosts; extra targets were not checked.</p>")
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_ns_hosts(observation: NsHostObservation) -> list[str]:
    parts = [
        "<h2>NS hosts</h2>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.status == "NOT DETECTED":
        parts.append("<p>No NS records at this name.</p>")
    for item in observation.checks:
        scope = "in-bailiwick" if item.in_bailiwick else "out-of-bailiwick"
        parts.append(
            f"<p><code>{_e(item.host)}</code> {_e(scope)} — "
            f"<strong>{_e(item.status)}</strong></p>"
        )
        if item.ipv4:
            parts.append(f"<p>A: <code>{_e(', '.join(item.ipv4))}</code></p>")
        if item.ipv6:
            parts.append(f"<p>AAAA: <code>{_e(', '.join(item.ipv6))}</code></p>")
        if item.error:
            parts.append(f"<p class=\"note\">{_e(item.error)}</p>")
    if observation.truncated:
        parts.append("<p class=\"note\">More than 8 NS hosts; extra targets were not checked.</p>")
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_cname_targets(observation: CnameTargetObservation) -> list[str]:
    parts = [
        "<h2>CNAME targets</h2>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.status == "NOT DETECTED":
        parts.append("<p>No CNAME records at this name.</p>")
    for item in observation.checks:
        parts.append(
            f"<p><code>{_e(item.target)}</code> — <strong>{_e(item.status)}</strong></p>"
        )
        if item.chain:
            parts.append(f"<p>Chain: <code>{_e(' -> '.join(item.chain))}</code></p>")
        if item.ipv4:
            parts.append(f"<p>A: <code>{_e(', '.join(item.ipv4))}</code></p>")
        if item.ipv6:
            parts.append(f"<p>AAAA: <code>{_e(', '.join(item.ipv6))}</code></p>")
        if item.error:
            parts.append(f"<p class=\"note\">{_e(item.error)}</p>")
    if observation.truncated:
        parts.append("<p class=\"note\">More than 8 CNAME targets; extra aliases were not checked.</p>")
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_soa_ns(observation: SoaNsObservation) -> list[str]:
    parts = [
        "<h2>SOA / NS</h2>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.status == "NOT DETECTED":
        parts.append("<p>No SOA record at this name.</p>")
    if observation.mname:
        parts.append(f"<p>Primary: <code>{_e(observation.mname)}</code></p>")
    if observation.serial:
        parts.append(f"<p>Serial: <code>{_e(observation.serial)}</code></p>")
    if observation.ns_hosts:
        parts.append(f"<p>NS: <code>{_e(', '.join(observation.ns_hosts))}</code></p>")
    elif observation.status == "NO NS":
        parts.append("<p>No NS records at this name.</p>")
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_caa(observation: CaaObservation) -> list[str]:
    parts = [
        "<h2>CAA</h2>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.status == "NOT DETECTED":
        parts.append("<p>No CAA records at this name.</p>")
    if observation.issue:
        parts.append(f"<p>issue: <code>{_e(', '.join(observation.issue))}</code></p>")
    if observation.issuewild:
        parts.append(
            f"<p>issuewild: <code>{_e(', '.join(observation.issuewild))}</code></p>"
        )
    if observation.iodef:
        parts.append(f"<p>iodef: <code>{_e(', '.join(observation.iodef))}</code></p>")
    if observation.properties:
        parts.append("<ul>")
        for item in observation.properties:
            critical = ", issuer critical" if item.issuer_critical else ""
            parts.append(
                "<li>"
                f'{item.flags} {_e(item.tag)} "{_e(item.value)}" '
                f"({_e(item.tag_meaning)}{_e(critical)})"
                "</li>"
            )
        parts.append("</ul>")
    if observation.truncated:
        parts.append(
            '<p class="note">more than 8 CAA records; extras were not listed.</p>'
        )
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_dkim(observation: DkimObservation) -> list[str]:
    parts = [
        "<h2>DKIM</h2>",
        f"<p>Selector: <code>{_e(observation.selector)}</code></p>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.key_type:
        parts.append(f"<p>Key type: {_e(observation.key_type)}</p>")
    if observation.revoked:
        parts.append("<p>Public key: empty (p=) — this selector is revoked</p>")
    elif observation.key_present:
        parts.append(f"<p>Public key: present ({observation.key_chars} characters)</p>")
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_srv(observation: SrvObservation) -> list[str]:
    parts = [
        "<h2>SRV</h2>",
        f"<p>Service: <code>{_e(observation.service)}/{_e(observation.protocol)}</code></p>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.records:
        parts.extend(
            [
                "<table>",
                "<thead><tr><th>Value</th><th>TTL</th><th>Priority</th></tr></thead>",
                "<tbody>",
            ]
        )
        for record in observation.records:
            priority = "" if record.priority is None else str(record.priority)
            parts.append(
                "<tr>"
                f"<td><code>{_e(record.value)}</code></td>"
                f"<td>{record.ttl}</td>"
                f"<td>{_e(priority)}</td>"
                "</tr>"
            )
            for label, value in record.details:
                parts.append(
                    f"<tr><td colspan=\"3\">{_e(label)}: {_e(value)}</td></tr>"
                )
        parts.extend(["</tbody>", "</table>"])
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_naptr(observation: NaptrObservation) -> list[str]:
    parts = [
        "<h2>NAPTR</h2>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.status == "NOT DETECTED":
        parts.append("<p>No NAPTR records at this name.</p>")
    if observation.rewrites:
        parts.extend(
            [
                "<table>",
                "<thead><tr><th>Order</th><th>Preference</th><th>Flags</th>"
                "<th>Services</th><th>Regexp</th><th>Replacement</th></tr></thead>",
                "<tbody>",
            ]
        )
        for item in observation.rewrites:
            parts.append(
                "<tr>"
                f"<td>{item.order}</td>"
                f"<td>{item.preference}</td>"
                f"<td><code>{_e(item.flags)}</code></td>"
                f"<td><code>{_e(item.services)}</code></td>"
                f"<td><code>{_e(item.regexp)}</code></td>"
                f"<td><code>{_e(item.replacement)}</code></td>"
                "</tr>"
            )
            parts.append(
                f"<tr><td colspan=\"6\">{_e(item.flags_meaning)}</td></tr>"
            )
        parts.extend(["</tbody>", "</table>"])
    if observation.truncated:
        parts.append(
            '<p class="note">more than 8 NAPTR records; extras were not listed.</p>'
        )
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_uri(observation: UriObservation) -> list[str]:
    parts = [
        "<h2>URI</h2>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.status == "NOT DETECTED":
        parts.append("<p>No URI records at this name.</p>")
    if observation.uris:
        parts.extend(
            [
                "<table>",
                "<thead><tr><th>Priority</th><th>Weight</th><th>Target</th>"
                "<th>Scheme</th></tr></thead>",
                "<tbody>",
            ]
        )
        for item in observation.uris:
            parts.append(
                "<tr>"
                f"<td>{item.priority}</td>"
                f"<td>{item.weight}</td>"
                f"<td><code>{_e(item.target)}</code></td>"
                f"<td><code>{_e(item.scheme)}</code></td>"
                "</tr>"
            )
            parts.append(
                f"<tr><td colspan=\"4\">{_e(item.scheme_meaning)}</td></tr>"
            )
        parts.extend(["</tbody>", "</table>"])
    if observation.truncated:
        parts.append(
            '<p class="note">more than 8 URI records; extras were not listed.</p>'
        )
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_dname(observation: DnameObservation) -> list[str]:
    parts = [
        "<h2>DNAME</h2>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.status == "NOT DETECTED":
        parts.append("<p>No DNAME records at this name.</p>")
    if observation.dnames:
        parts.append("<ul>")
        for item in observation.dnames:
            parts.append(f"<li>target <code>{_e(item.target)}</code></li>")
        parts.append("</ul>")
    if observation.truncated:
        parts.append(
            '<p class="note">more than 8 DNAME records; extras were not listed.</p>'
        )
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_ipseckey(observation: IpseckeyObservation) -> list[str]:
    parts = [
        "<h2>IPSECKEY</h2>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.status == "NOT DETECTED":
        parts.append("<p>No IPSECKEY records at this name.</p>")
    if observation.ipseckeys:
        parts.extend(
            [
                "<table>",
                "<thead><tr><th>Precedence</th><th>Gateway type</th>"
                "<th>Algorithm</th><th>Gateway</th><th>Key length</th>"
                "</tr></thead>",
                "<tbody>",
            ]
        )
        for item in observation.ipseckeys:
            parts.append(
                "<tr>"
                f"<td>{item.precedence}</td>"
                f"<td>{item.gateway_type} {_e(item.gateway_type_meaning)}</td>"
                f"<td>{item.algorithm} {_e(item.algorithm_meaning)}</td>"
                f"<td><code>{_e(item.gateway)}</code></td>"
                f"<td>{item.key_length}</td>"
                "</tr>"
            )
        parts.extend(["</tbody>", "</table>"])
    if observation.truncated:
        parts.append(
            '<p class="note">more than 8 IPSECKEY records; extras were not listed.</p>'
        )
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_smimea(observation: SmimeaObservation) -> list[str]:
    parts = [
        "<h2>SMIMEA</h2>",
        f"<p>Local-part: <code>{_e(observation.local_part)}</code></p>",
        f"<p>Queried: <code>{_e(observation.query_name)}</code></p>",
        f"<p>Status: <strong>{_e(observation.status)}</strong></p>",
    ]
    if observation.status == "NOT DETECTED":
        parts.append("<p>No SMIMEA records for this local-part.</p>")
    if observation.associations:
        parts.extend(
            [
                "<table>",
                "<thead><tr><th>Usage</th><th>Selector</th>"
                "<th>Matching</th><th>Association length</th>"
                "</tr></thead>",
                "<tbody>",
            ]
        )
        for item in observation.associations:
            parts.append(
                "<tr>"
                f"<td>{item.usage} {_e(item.usage_meaning)}</td>"
                f"<td>{item.selector} {_e(item.selector_meaning)}</td>"
                f"<td>{item.matching_type} {_e(item.matching_meaning)}</td>"
                f"<td>{item.association_length}</td>"
                "</tr>"
            )
        parts.extend(["</tbody>", "</table>"])
    if observation.truncated:
        parts.append(
            '<p class="note">more than 8 SMIMEA records; extras were not listed.</p>'
        )
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
    parts.append(f"<p class=\"note\">{_e(observation.note)}</p>")
    return parts


def _html_security(report: SecurityReport) -> list[str]:
    parts = [
        "<h2>Security analysis</h2>",
        f"<p class=\"note\">{_e(report.disclaimer)}</p>",
        f"<p>Score: <span class=\"band\">{report.risk.value}/100 {_e(report.risk.band)}</span></p>",
        f"<p class=\"note\">{_e(report.risk.note)}</p>",
    ]
    if report.risk.contributions:
        parts.append("<ul>")
        for item in report.risk.contributions:
            parts.append(f"<li>+{item.points} {_e(item.label)}</li>")
        parts.append("</ul>")
    if not report.findings:
        parts.append("<p>No findings from this pass.</p>")
        return parts
    for finding in report.findings:
        sev = finding.severity if finding.severity in {"info", "low", "medium", "high"} else "info"
        parts.extend(
            [
                f"<article class=\"finding sev-{sev}\">",
                f"<p><strong>[{_e(finding.severity.upper())}] {_e(finding.title)}</strong></p>",
                f"<p>{_e(finding.description)}</p>",
                f"<p>Recommendation: {_e(finding.recommendation)}</p>",
                "</article>",
            ]
        )
    return parts


def _html_comparison(comparison: ResolverComparison) -> list[str]:
    parts = [
        "<h2>Resolver comparison</h2>",
        f"<p>Status: <strong>{_e(comparison.status)}</strong> · primary {_e(comparison.primary)}</p>",
        f"<p class=\"note\">{_e(comparison.note)}</p>",
    ]
    for snap in comparison.snapshots:
        parts.append(f"<h3>{_e(snap.name)}</h3>")
        if snap.error:
            parts.append(f"<p class=\"note\">{_e(snap.error)}</p>")
        for label, values in snap.answers.items():
            shown = ", ".join(values) if values else "(none)"
            parts.append(f"<p>{_e(label)}: <code>{_e(shown)}</code></p>")
    return parts

