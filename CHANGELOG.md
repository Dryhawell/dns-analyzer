# Changelog

All notable changes to DNS Analyzer are documented here.

## 1.12.0 — 2026-09-10

MX host address lookup. SMTP is not probed.

### Added

- Default / `--security` / `--all` resolve A/AAAA for up to 8 MX targets
- CLI/JSON/HTML show `RESOLVES` / `NO ADDRESS` / `NXDOMAIN` / `UNREADABLE` / `NULL MX`
- Findings: `mx_unreadable` / `mx_host_unreadable` / `mx_host_nxdomain` / `mx_host_no_address` are info (+0)

### Notes

- MX names a host; this tool does not open TCP/25
- Missing MX is common for names that are not mail domains
- RFC 7505 null MX (`.`) is not treated as a missing address

## 1.11.0 — 2026-09-08

Forward-confirmed reverse DNS (FCrDNS). The IP is not contacted.

### Added

- Default / `--security` / `--all` check up to 8 A/AAAA addresses: PTR, then forward A/AAAA
- CLI/JSON/HTML show `CONFIRMED` / `NO PTR` / `MISMATCH` / `UNREADABLE`
- Findings: `fcrdns_no_ptr` / `fcrdns_mismatch` / `fcrdns_unreadable` are info (+0)

### Notes

- FCrDNS does not open a connection to the address
- Missing PTR is common; a mismatch is not treated as hijacking

## 1.10.0 — 2026-09-08

SSHFP DNS discovery (RFC 4255). SSH is not probed.

### Added

- Default / `--security` / `--all` query SSHFP at the scanned hostname
- CLI/JSON/HTML show algorithm, fingerprint type, and fingerprint hex
- Findings: `sshfp_missing` / `sshfp_unreadable` are info (+0)

### Notes

- This is a DNS record, not an SSH scan; port 22 is not opened
- Missing SSHFP is common and is not treated as a compromise
- `--record SSHFP` is rejected; the record is part of the security view

## 1.9.0 — 2026-09-08

DANE TLSA DNS discovery (RFC 6698). TLS is not probed.

### Added

- Default / `--security` / `--all` query TLSA at `_443._tcp.<domain>` (HTTPS DANE)
- CLI/JSON/HTML show usage / selector / matching type and association hex (long values truncated)
- Findings: `tlsa_missing` / `tlsa_unreadable` are info (+0)

### Notes

- Only 443/tcp is queried; MX hosts and other ports are not followed
- This is a DNS record, not a TLS handshake or certificate check
- Missing TLSA is common and is not treated as a compromise
- `--record TLSA` is rejected (TLSA is not at the apex)

## 1.8.0 — 2026-09-08

BIMI DNS discovery (RFC 9091). Logo and VMC URLs are not fetched.

### Added

- Default / `--security` / `--all` query TXT at `default._bimi.<domain>` (`v=BIMI1; l=...; a=...`)
- CLI/JSON/HTML show `l=` (logo URL) and `a=` (authority/VMC URL) without HTTP GET
- Findings: `bimi_missing` / `bimi_unreadable` / `bimi_location_missing` / `bimi_without_enforcing_dmarc` are info (+0); multiple TXT is low (+5)

### Notes

- Only the well-known selector `default` is queried; other selectors are not guessed
- BIMI is a logo URL on aligned mail, not a certificate of authenticity
- Missing BIMI is common and is not treated as a compromise

## 1.7.0 — 2026-09-07

TLS-RPT DNS discovery (RFC 8460). SMTP is not probed; HTTPS rua URLs are not fetched.

### Added

- Default / `--security` / `--all` query TXT at `_smtp._tls.<domain>` (`v=TLSRPTv1; rua=...`)
- CLI/JSON/HTML show `rua=` (mailto: or https:)
- Findings: `tlsrpt_missing` / `tlsrpt_unreadable` / `tlsrpt_rua_missing` are info (+0); multiple TXT is low (+5)

### Notes

- TLS-RPT is a report destination, not a TLS enforcement policy (that is MTA-STS)
- Missing TLS-RPT is common and is not treated as a compromise

## 1.6.0 — 2026-09-07

MTA-STS DNS discovery (RFC 8461). The HTTPS policy file is not fetched.

### Added

- Default / `--security` / `--all` query TXT at `_mta-sts.<domain>` (`v=STSv1; id=...`)
- CLI/JSON/HTML show the id and the policy host `mta-sts.<domain>` (no HTTP GET)
- Findings: `mtasts_missing` / `mtasts_unreadable` / `mtasts_id_missing` are info (+0); multiple TXT is low (+5)

### Notes

- This is not an SMTP or STARTTLS scanner
- Missing MTA-STS is common and is not treated as a compromise

## 1.5.0 — 2026-09-07

Opt-in SRV lookup (RFC 2782). Service names are never guessed.

### Added

- `--srv SERVICE` (repeatable, max 8) queries `_SERVICE._tcp.<domain>` (or `SERVICE/udp`)
- CLI/JSON/HTML show priority, weight, port, and target; target `.` means the service is not offered
- Findings only for services you named (`srv_missing` / `srv_unreadable` are info, +0)
- `--record SRV` is rejected with a hint to use `--srv`

### Notes

- Default / `--all` / `--security` still do **not** hunt sip, xmpp, minecraft, or any other service
- SRV is not at the apex; it is not part of `CORE_TYPES`

## 1.4.0 — 2026-09-07

One-hop SPF `include:` / `redirect=` lookup. Not a full RFC 7208 evaluator.

### Added

- After the apex `v=spf1` record is found, `include:` and `redirect=` names are queried (max 10)
- Nested `include:` names are listed and **not** followed; `a` / `mx` / `ptr` / `exists` are not evaluated
- Void include: is a low finding (`spf_include_missing`); include timeout is info (`spf_include_unreadable`, +0)

### Notes

- This does not compute an SPF pass/fail for a sending IP
- Apex `+all` is still scored from the apex policy only

## 1.3.0 — 2026-09-06

HTTPS and SVCB records (RFC 9460). These are DNS types, not an HTTP scan.

### Added

- Forward lookup for **HTTPS** (type 65) and **SVCB** (type 64)
- AliasMode vs ServiceMode, ALPN, port, address hints; ECH is reported as present (config not dumped)
- `--record HTTPS` / `--record SVCB`; default `--all` includes them
- Missing HTTPS/SVCB is not scored and is not a finding

### Notes

- HTTPS in DNS is not “the website”. Browsers use it for HTTP/3 / ECH hints
- `--security` still skips these types (they are not SPF/DMARC/CAA)

## 1.2.0 — 2026-09-06

Opt-in DKIM selector lookup. Selectors are never guessed.

### Added

- `--dkim SELECTOR` (repeatable, max 8) queries `SELECTOR._domainkey.<domain>` TXT
- Parse `v=DKIM1` (`k=`, `p=`); empty `p=` is **revoked**, not a missing domain
- JSON/HTML `dkim` observations; CLI shows key type and length, not the raw key
- Findings only for selectors you named (`dkim_selector_missing` is +0)

### Notes

- Default / `--all` / `--security` still do **not** hunt DKIM keys
- Read the selector from a signed message (`s=` in `DKIM-Signature`), then pass `--dkim`

## 1.1.0 — 2026-09-06

HTML reports for sharing a scan in a browser. JSON remains the machine schema.

### Added

- `--format html` and `.html` `--output` paths: a self-contained page (inline CSS, no JavaScript, no CDN)
- DNS values are HTML-escaped so a TXT string cannot inject markup

### Notes

- HTML is for humans. Automate against JSON (`dns-analyzer.report.v1`), not the HTML DOM
- Still not a vulnerability scanner

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
