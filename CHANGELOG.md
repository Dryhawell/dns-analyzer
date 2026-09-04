# Changelog

All notable changes to DNS Analyzer are documented here.

## 1.0.0 — 2026-09-04

First stable release. The CLI analyzes how a name is published in DNS and reports configuration signals. It is **not** a vulnerability scanner.

### Added

- Forward lookup for A, AAAA, CNAME, MX, NS, TXT, SOA, and CAA; reverse lookup (`--reverse`) for PTR
- DNSSEC visibility (DNSKEY / DS / AD flag), SPF and DMARC parsing, CAA inspection
- Security findings with severity and stable `code` values; local 0–100 risk heuristic (not CVSS)
- JSON (`dns-analyzer.report.v1`) and CSV export; rotating file log without rdata
- Optional multi-resolver A/AAAA comparison from a JSON config (no hardcoded public DNS IPs)
- `--version` (`1.0.0`); JSON reports include `tool_version`

### Notes

- Missing DNSSEC, SPF, DMARC, or CAA is an observation, not proof of compromise
- DNSSEC here is what **this resolver** can see, not a full chain to the IANA root
- Out of v1: GUI, subdomain brute-force, WHOIS, geolocation, HTML/PDF, DKIM selector discovery
