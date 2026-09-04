"""Serialize DNSAnalysisResult to JSON or CSV.

The JSON schema is versioned (dns-analyzer.report.v1) so other tools can
consume reports without scraping CLI text. This is not a logging module.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from analyzer.compare import ResolverComparison
from analyzer.dmarc import DmarcObservation
from analyzer.dnssec import DnssecObservation
from analyzer.models import DNSRecord
from analyzer.result import DNSAnalysisResult
from analyzer.risk import RiskScore
from analyzer.security import SecurityFinding, SecurityReport
from analyzer.spf import SpfObservation
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


def write_json(path: Path, result: DNSAnalysisResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dumps_json(result), encoding="utf-8")


def write_csv(path: Path, result: DNSAnalysisResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        _write_csv_rows(handle, result)


def write_report(path: Path, result: DNSAnalysisResult, fmt: str) -> None:
    if fmt == "json":
        write_json(path, result)
        return
    if fmt == "csv":
        write_csv(path, result)
        return
    raise ValueError(f"Unsupported export format: {fmt}")


def format_from_suffix(path: Path) -> str | None:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix == ".csv":
        return "csv"
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
