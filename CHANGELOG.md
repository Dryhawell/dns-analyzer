# Changelog

All notable changes to DNS Analyzer are documented here.

## 1.29.0 — 2026-09-23

CERT listing. Certificates in DNS are listed; bytes are not dumped and PKIX is not validated.

### Added

- Opt-in `--cert` lists up to 8 CERT records (type, key tag, algorithm, certificate length)
- CLI/JSON/HTML include `cert` only when `--cert` is used
- Findings: `cert_missing` / `cert_unreadable` are info (+0)
- `--record CERT` is rejected with a hint to use `--cert`

### Notes

- Missing CERT is common and is not a compromise
- Certificate / CRL bytes are not dumped; only length is listed
- PKIX is not validated; CAs are not contacted
- Type URI / OID pointers are not fetched
- Listing a CERT record is not proof that a TLS certificate is in DNS
- CERT is not TLSA and is not a replacement for CAA

## 1.28.0 — 2026-09-22

OPENPGPKEY listing. OpenPGP keys in DNS are listed; key bytes are not dumped.

### Added

- Opt-in `--openpgpkey LOCALPART` lists up to 8 OPENPGPKEY records per local-part (key length only)
- CLI/JSON/HTML include `openpgpkey` only when `--openpgpkey` is used
- Findings: `openpgpkey_missing` / `openpgpkey_unreadable` are info (+0)
- `--record OPENPGPKEY` is rejected with a hint to use `--openpgpkey`

### Notes

- Missing OPENPGPKEY is common and is not a compromise
- Local-parts are never guessed; pass the mailbox local-part (the part before @)
- This tool does not send email, contact a keyserver, or invoke GnuPG
- Key bytes are not dumped; only key length is listed
- Listing an OPENPGPKEY record is not proof that this mailbox uses working OpenPGP
- OPENPGPKEY is OpenPGP in DNS (RFC 7929), not SMIMEA

## 1.27.0 — 2026-09-22

SMIMEA listing. DANE for S/MIME is listed; certificates are not fetched.

### Added

- Opt-in `--smimea LOCALPART` lists up to 8 SMIMEA records per local-part (usage, selector, matching, association length)
- CLI/JSON/HTML include `smimea` only when `--smimea` is used
- Findings: `smimea_missing` / `smimea_unreadable` are info (+0)
- `--record SMIMEA` is rejected with a hint to use `--smimea`

### Notes

- Missing SMIMEA is common and is not a compromise
- Local-parts are never guessed; pass the mailbox local-part (the part before @)
- This tool does not send email or fetch certificates
- Association bytes are not dumped; only association length is listed
- Listing a SMIMEA record is not S/MIME or certificate validation
- SMIMEA is DANE for S/MIME (RFC 8162), not TLSA for HTTPS

## 1.26.0 — 2026-09-19

IPSECKEY listing. IPsec is not probed and key material is not dumped.

### Added

- Opt-in `--ipseckey` lists up to 8 IPSECKEY records (precedence, gateway type, algorithm, gateway, key length)
- CLI/JSON/HTML include `ipseckey` only when `--ipseckey` is used
- Findings: `ipseckey_missing` / `ipseckey_unreadable` are info (+0)
- `--record IPSECKEY` is rejected with a hint to use `--ipseckey`

### Notes

- Missing IPSECKEY is common and is not a compromise
- This tool does not probe IPsec or IKE
- Key material is not dumped; only key length is listed
- A gateway domain name is not resolved or followed
- A published gateway is text in DNS, not an IPsec session this tool established

## 1.25.0 — 2026-09-19

RRSIG listing. Signatures are listed, not validated.

### Added

- Default / `--security` / `--all` list up to 8 RRSIG records (type covered, algorithm, labels, original TTL, inception, expiration, key tag, signer, signature length)
- CLI/JSON/HTML include `rrsig`
- Findings: `rrsig_missing` / `rrsig_unreadable` are info (+0)
- `--record RRSIG` is rejected with a hint to use default / `--security`

### Notes

- Missing RRSIG is common on unsigned zones and is not broken DNSSEC
- This tool does not validate signatures or check the key tag against DNSKEY
- This tool does not walk the chain of trust
- Signature bytes are not dumped; only signature length is listed
- Inception and expiration are listed as published UTC; this is not a valid/invalid verdict

## 1.24.0 — 2026-09-19

DNAME listing. CNAME is not synthesized and the subtree is not walked.

### Added

- Opt-in `--dname` lists up to 8 DNAME targets
- CLI/JSON/HTML include `dname` only when `--dname` is used
- Findings: `dname_missing` / `dname_unreadable` are info (+0)
- `--record DNAME` is rejected with a hint to use `--dname`

### Notes

- Missing DNAME is common and is not a compromise
- This tool does not synthesize CNAME records for names under the node
- This tool does not walk the subtree
- This tool does not fetch HTTP
- A published target is a DNS suffix, not a site this tool visited

## 1.23.0 — 2026-09-16

ZONEMD listing. The zone digest is listed, not recomputed and not fetched via AXFR.

### Added

- Default / `--security` / `--all` list up to 8 ZONEMD records (serial, scheme, hash algorithm, digest length)
- CLI/JSON/HTML include `zonemd`
- Findings: `zonemd_missing` / `zonemd_unreadable` are info (+0)
- `--record ZONEMD` is rejected with a hint to use default / `--security`

### Notes

- Missing ZONEMD is common and is not broken DNSSEC
- This tool does not AXFR/IXFR the zone or recompute the digest
- Digest bytes are not dumped; only digest length is listed
- The serial is a change counter, not a security score

## 1.22.0 — 2026-09-15

CSYNC listing. Child-to-parent NS/A/AAAA signaling is listed, not applied.

### Added

- Default / `--security` / `--all` list up to 8 CSYNC records (serial, flags, immediate, soaminimum, type bitmap)
- CLI/JSON/HTML include `csync`
- Findings: `csync_missing` / `csync_unreadable` are info (+0)
- `--record CSYNC` is rejected with a hint to use default / `--security`

### Notes

- Missing CSYNC is common and is not broken DNS
- This tool does not contact the parent registry or update parent delegation
- CSYNC is not compared to the child NS set
- The serial is a change counter for the parent, not a security score

## 1.21.0 — 2026-09-15

NSEC / NSEC3PARAM listing. Authenticated denial is listed at this name; the chain is not walked.

### Added

- Default / `--security` / `--all` list up to 8 NSEC3PARAM records (hash algorithm, flags, opt-out, iterations, salt length) and 8 NSEC records (next name, type bitmap)
- CLI/JSON/HTML include `nsec` with `nsec` and `nsec3param` arrays
- Findings: `nsec_missing` / `nsec_unreadable` are info (+0)
- `--record NSEC`, `--record NSEC3`, and `--record NSEC3PARAM` are rejected with a hint to use default / `--security`

### Notes

- Missing NSEC/NSEC3PARAM is common on unsigned zones and is not broken DNSSEC
- This tool does not walk NSEC/NSEC3 (zone enumeration) and does not query NSEC3
- Salt bytes are not dumped; only salt length is listed
- A listed next name is an observation at this query name, not a follow-up lookup

## 1.20.0 — 2026-09-14

CDS and CDNSKEY listing. Child-to-parent DS signaling is listed, not submitted.

### Added

- Default / `--security` / `--all` list up to 8 CDS records (algorithm, digest type) and 8 CDNSKEY records (flags, algorithm, KSK/ZSK)
- CLI/JSON/HTML include `cds` with `cds` and `cdnskey` arrays
- Findings: `cds_missing` / `cds_unreadable` are info (+0)
- `--record CDS` and `--record CDNSKEY` are rejected with a hint to use default / `--security`

### Notes

- Missing CDS is common and is not broken DNSSEC
- This tool does not check that CDS matches DNSKEY or DS
- This tool does not contact the parent registry or submit a DS update
- Digest bytes and public key material are not dumped

## 1.19.0 — 2026-09-14

URI listing. The target is not fetched and service prefixes are not guessed.

### Added

- Opt-in `--uri` lists up to 8 URI records (priority, weight, target, scheme)
- CLI/JSON/HTML include `uri` only when `--uri` is used
- Findings: `uri_missing` / `uri_unreadable` are info (+0)
- `--record URI` is rejected with a hint to use `--uri`

### Notes

- Default / `--security` / `--all` do not query URI unless `--uri` is passed
- Listing an https/ftp/sip URI is not a fetch, login, or call
- This tool does not guess prefixes such as `_http._tcp`

## 1.18.0 — 2026-09-14

NAPTR rewrite listing. The regexp is not executed and ENUM/SIP names are not guessed.

### Added

- Opt-in `--naptr` lists up to 8 NAPTR records (order, preference, flags, services, regexp, replacement)
- CLI/JSON/HTML include `naptr` only when `--naptr` is used
- Findings: `naptr_missing` / `naptr_unreadable` are info (+0)
- `--record NAPTR` is rejected with a hint to use `--naptr`

### Notes

- Default / `--security` / `--all` do not query NAPTR unless `--naptr` is passed
- Listing a regexp or `E2U+sip` is not a SIP scan and is not a rewrite
- This tool does not follow flag S/A replacement lookups

## 1.17.0 — 2026-09-14

CAA issue / issuewild / iodef listing. Certificate authorities are not contacted.

### Added

- Default / `--security` / `--all` summarize up to 8 CAA properties (`issue`, `issuewild`, `iodef`)
- CLI/JSON/HTML include `caa` with property flags, tag meaning, and grouped values
- Findings: `caa_unreadable` is info (+0); missing CAA stays `caa_missing` (+2)

### Notes

- Listing a CA name is not proof that a certificate was issued
- This tool does not talk to CAs or check Certificate Transparency logs
- `;` as an issue value means no CA is authorized for that property
- CAs may walk to a parent name when this name has no CAA

## 1.16.0 — 2026-09-13

DNSKEY and DS algorithm listing. The chain to the IANA root is not validated.

### Added

- Default / `--security` / `--all` list up to 8 DNSKEY records (flags, algorithm, KSK/ZSK, key tag)
- DS delegations show algorithm and digest type (digest bytes are not dumped)
- CLI/JSON/HTML include `keys` and `delegations`
- Findings: `dnssec_sha1_algorithm` / `dnssec_sha1_ds` are info (+0)

### Notes

- DETECTED / NOT DETECTED is unchanged: still DNSKEY or DS visible to this resolver
- Listing RSA/SHA-1 or SHA-1 DS is not a compromise
- This tool does not validate signatures or the parent chain

## 1.15.0 — 2026-09-13

SOA primary vs NS set. Zone transfer is not attempted.

### Added

- Default / `--security` / `--all` compare SOA mname to the NS set
- CLI/JSON/HTML show `ALIGNED` / `HIDDEN PRIMARY` / `NO NS` / `NOT DETECTED` / `UNREADABLE`
- Findings: `soa_ns_unreadable` / `soa_hidden_primary` / `soa_without_ns` are info (+0)

### Notes

- A hidden primary (mname not in NS) is a common, valid design
- This tool does not contact the primary or attempt AXFR
- Missing SOA is common on subdomains

## 1.14.0 — 2026-09-11

CNAME target address lookup. HTTP is not fetched.

### Added

- Default / `--security` / `--all` follow up to 8 CNAME targets (max 5 hops) and resolve A/AAAA
- CLI/JSON/HTML show `RESOLVES` / `NO ADDRESS` / `NXDOMAIN` / `UNREADABLE` / `LOOP` / `TOO DEEP`
- Findings: `cname_target_*` are info (+0) and are not treated as takeover

### Notes

- CNAME names another host; this tool does not fetch HTTP
- Apex names often have no CNAME
- When this check runs, the older `cname_dangling` heuristic is not also applied

## 1.13.0 — 2026-09-11

NS host address lookup. Zone transfer is not attempted.

### Added

- Default / `--security` / `--all` resolve A/AAAA for up to 8 NS targets
- CLI/JSON/HTML show `RESOLVES` / `NO ADDRESS` / `NXDOMAIN` / `UNREADABLE` and in-bailiwick vs out-of-bailiwick
- Findings: `ns_unreadable` / `ns_host_unreadable` / `ns_host_nxdomain` / `ns_host_no_address` are info (+0)

### Notes

- NS names a host; this tool does not open TCP/53 to the NS or attempt AXFR
- Missing NS is common on subdomains; the parent holds the delegation
- A missing address is not treated as lame-server proof

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
