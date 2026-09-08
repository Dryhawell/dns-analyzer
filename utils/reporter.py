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

from analyzer.compare import ResolverComparison
from analyzer.dmarc import DmarcObservation
from analyzer.dkim import DkimObservation
from analyzer.dnssec import DnssecObservation
from analyzer.models import DNSRecord
from analyzer.mtasts import MtaStsObservation
from analyzer.result import DNSAnalysisResult
from analyzer.risk import RiskScore
from analyzer.security import SecurityFinding, SecurityReport
from analyzer.spf import SpfObservation
from analyzer.srv import SrvObservation
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
        "dkim": [_dkim_dict(item) for item in result.dkim] if result.dkim is not None else None,
        "srv": [_srv_dict(item) for item in result.srv] if result.srv is not None else None,
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
    if result.spf is not None:
        parts.extend(_html_spf(result.spf))
    if result.dmarc is not None:
        parts.extend(_html_dmarc(result.dmarc))
    if result.mta_sts is not None:
        parts.extend(_html_mta_sts(result.mta_sts))
    if result.tls_rpt is not None:
        parts.extend(_html_tls_rpt(result.tls_rpt))
    if result.dkim:
        for item in result.dkim:
            parts.extend(_html_dkim(item))
    if result.srv:
        for item in result.srv:
            parts.extend(_html_srv(item))
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
        f"<p class=\"note\">{_e(observation.note)}</p>",
    ]
    if observation.error:
        parts.append(f"<p class=\"note\">{_e(observation.error)}</p>")
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

