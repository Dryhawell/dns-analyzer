# DNS Analyzer

Professional DNS analysis CLI: it reads how a name is published, interprets security-related DNS signals, and writes a report you can share or pipe to other tools.

> **Current status:** **v1.12.0** — see [CHANGELOG.md](CHANGELOG.md).

This is **not** a vulnerability scanner. Missing records (DNSSEC, SPF, DMARC, CAA, SRV) are observations, not automatic proof of compromise.

---

## Overview

DNS Analyzer takes a domain (`example.com` or a URL) or an IP (`--reverse`) and:

1. Validates and normalizes the input
2. Queries selected DNS record types (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, HTTPS, SVCB, PTR)
3. Inspects security-related signals (DNSSEC, SPF, DMARC, CAA, MTA-STS, TLS-RPT, BIMI, DANE TLSA, SSHFP, FCrDNS, MX hosts, optional DKIM / SRV)
4. Prints a readable CLI report and can export JSON, CSV, or HTML

Three layers:

| Layer | What it answers |
| --- | --- |
| DNS Records | How is this name published on the internet? |
| DNS Security | Which email / authenticity / certificate policies are visible? |
| Network | How do resolvers, TTL, caching, and reverse DNS behave? |

### How DNS works (in this tool)

A hostname is not a website. DNS is a distributed database that answers **questions about names**.

```
You  →  Recursive resolver (ISP / OS / --nameserver)
              →  Root  →  TLD  →  Authoritative nameservers for the zone
```

- **Stub / this CLI** — builds a query and shows the answer. It does not walk the root itself.
- **Recursive resolver** — does the hunting (or uses cache) and returns a response.
- **Authoritative server** — is the source of truth for a zone (the NS / SOA you see).

`dnspython` sends a DNS message (RFC 1035) to a recursive resolver, usually UDP/53 (TCP if the answer is truncated). By default that recursive list is the **operating system resolver** (the same path `nslookup` uses). Nameserver IPs are not compiled into the program.

NXDOMAIN on **A** aborts a forward scan: if the name does not exist, later types are not asked. A timeout on CAA does not discard A/MX; that section reports the error and the rest stays.

---

## Features

- Domain validation and URL → domain normalization
- Record lookup via dnspython (OS resolver, `--nameserver`, or `--config`)
- Query only the types you asked for (`--record`); A is still queried first so NXDOMAIN can abort
- Controlled parallelism after A (dnspython `Resolver` is locked; it is not thread-safe)
- TTL display (cache lifetime, never a security score)
- DNSSEC **detection** (DNSKEY / DS / AD flag), not a full chain-of-trust validator
- SPF and DMARC parsing from TXT; `include:` followed one hop; DKIM and SRV are opt-in
- MTA-STS TXT at `_mta-sts` (RFC 8461); the HTTPS policy file is not fetched
- TLS-RPT TXT at `_smtp._tls` (RFC 8460); SMTP is not probed
- BIMI TXT at `default._bimi` (RFC 9091); logo and VMC URLs are not fetched
- DANE TLSA at `_443._tcp` (RFC 6698); TLS is not probed
- SSHFP at the hostname (RFC 4255); SSH is not probed
- FCrDNS for A/AAAA (PTR then forward); the IP is not contacted
- MX host A/AAAA (RFC 5321); SMTP is not probed
- CAA inspection
- HTTPS / SVCB (RFC 9460) — ALPN, port, ECH presence; not an HTTP scanner
- Reverse DNS (`PTR`)
- Security findings with severity, description, recommendation, and a stable `code`
- Transparent risk score (local heuristic, 0–100; not CVSS)
- JSON (`dns-analyzer.report.v1`), CSV, and self-contained HTML export
- Optional DKIM selector lookup (`--dkim`; selectors are never guessed)
- Optional SRV lookup (`--srv`; service names are never guessed)
- Optional multi-resolver A/AAAA comparison from a JSON config (no hardcoded public DNS IPs)
- File logging (`logs/dns-analyzer.log`; no secrets or rdata values)
- Unit tests with mocks (no live nameservers)

**Not in this release:** GUI, aggressive subdomain brute-force, WHOIS, geolocation, PDF reports, DKIM selector hunting, BIMI selector hunting, SRV service hunting.

---

## Why DNS Security Matters

DNS maps names to infrastructure. If that mapping is spoofed (**DNS spoofing**), hijacked, or weakly configured, browsers and mail can go to the wrong place.

This tool teaches you to **read** DNS:

- What is published (records)
- What receivers or CAs are told to do (SPF, DMARC, CAA)
- Whether *this resolver* can see DNSSEC signals
- Whether two recursive resolvers disagree on A/AAAA (often geo-DNS, not a crime)

It does **not** assign CVEs, does **not** prove a domain is compromised, and does **not** replace `dig` plus operator judgment.

---

## DNS Record Types

| Type | Meaning | Missing means |
| --- | --- | --- |
| **A** | Hostname → IPv4 address | This name has no IPv4 mapping (it may still have AAAA) |
| **AAAA** | Hostname → IPv6 address | This name has no IPv6 mapping (very common; not a vulnerability) |
| **CNAME** | This name is an alias for another name | The name is not an alias (typical at the zone apex) |
| **MX** | Where email for this name should be delivered | This name is not advertised as a mail domain |
| **NS** | Authoritative nameservers for this zone | Common on subdomains; the parent zone holds delegation |
| **TXT** | Free-form text (SPF, verification tokens, policies) | No published text records at this name |
| **SOA** | Start of authority: primary NS, serial, timers | Common on subdomains; SOA lives at the zone apex |
| **CAA** | Which certificate authorities may issue TLS certs | CAs may fall back to parent names; not automatically unsafe |
| **HTTPS** | Service parameters for this name (ALPN, port, ECH) — DNS type 65, RFC 9460 | Common; browsers then use A/AAAA. Not a missing website |
| **SVCB** | Generic service binding (same wire format as HTTPS) | Common; not a vulnerability |
| **SRV** | Service location (`_service._proto`) — host, port, priority (RFC 2782) | Opt-in via `--srv`; never guessed. Missing is not a compromise |
| **PTR** | IP → hostname (reverse DNS, under in-addr.arpa / ip6.arpa) | The address has no published reverse name |

TTL is shown next to each record as a **cache lifetime**, never as a security score. MX and SRV **priority**: lower number is tried first.

### TTL, caching, and propagation

TTL (Time To Live) is how long a resolver may reuse an answer without asking again.

- **Low TTL** — a change becomes visible sooner; resolvers also query more often.
- **High TTL** — less query load, but after you change a record some users keep the old answer until their cache expires. That delay is **DNS propagation**. It is not a global countdown; each resolver has its own remaining TTL.

Values here are often **remaining TTL at this resolver**, not always the original zone TTL. A 60-second A record is not "insecure". An 86400-second NS record is not "secure". They are operational choices.

---

## Installation

Python **3.12+**

```bash
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
pip install -r requirements.txt
```

Linux / macOS:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

Dependencies: `dnspython`, `pytest` (see `requirements.txt`). No extra YAML library; resolver config is JSON.

---

## Usage

```bash
python main.py example.com
python main.py example.com --all
python main.py example.com --record A
python main.py example.com --record MX --record NS
python main.py example.com --record HTTPS
python main.py example.com --security
python main.py example.com --dkim google
python main.py example.com --srv sip
python main.py https://example.com/login
python main.py example.com --timeout 3
python main.py example.com --format json
python main.py example.com --format html --output reports/example_com.html
python main.py example.com --output reports/example_com.json
python main.py example.com --format csv --output reports/example_com.csv
python main.py example.com --config config/resolvers.example.json
python main.py example.com --nameserver 192.0.2.53
python main.py --reverse 8.8.8.8 --format json
python main.py --version
```

| Mode | What you get |
| --- | --- |
| (default) or `--all` | Every core record type, TTL summary, DNSSEC, SPF, DMARC, MTA-STS, TLS-RPT, BIMI, DANE TLSA, SSHFP, FCrDNS, MX hosts, findings, risk score |
| `--record TYPE` | Only that type (repeatable). Skips security queries. Other types are not queried; **A is still queried first** so NXDOMAIN can abort |
| `--security` | DNSSEC / SPF / DMARC / MTA-STS / TLS-RPT / BIMI / DANE TLSA / SSHFP / FCrDNS / MX hosts / findings / score, without the record dump. Queries A, AAAA, CNAME, TXT, CAA (not MX/NS/SOA/HTTPS/SVCB dump; MX is still queried for host addresses) |
| `--dkim SELECTOR` | TXT at `SELECTOR._domainkey.<domain>`. Repeatable (max 8). Never guessed |
| `--srv SERVICE` | SRV at `_SERVICE._tcp.<domain>` (or `SERVICE/udp`). Repeatable (max 8). Never guessed |
| `--record A --security` | That type plus the security sections |
| `--reverse IP` | PTR only |
| `--format json` / `csv` / `html` | Machine or HTML stdout (no human dump) |
| `--output PATH` | Write `.json`, `.csv`, or `.html`; with default text mode the human report still prints |
| `--config PATH` | Named recursive resolvers from JSON. Two or more compare **A/AAAA** |
| `--resolver NAME` | Pick names from `--config` (repeatable). First is the primary scan |
| `--nameserver IP` | Use this recursive resolver instead of the OS list (repeatable). Not combined with `--config` |
| `--version` | Print `dns-analyzer 1.12.0` and exit |

`--timeout` must be between 0 (exclusive) and 120 seconds. Default is 5. Each nameserver waits that long; **lifetime** is timeout × (up to 4 nameservers) so a dead first recursive server can fail over.

| Exit code | Meaning |
| --- | --- |
| **0** | Success (including “no PTR found” on reverse) |
| **1** | Invalid input, DNS/network failure, or could not write a report |
| **130** | Interrupted (Ctrl+C) |

The program does not print a traceback for expected DNS or CLI errors. Unexpected failures log a traceback to the log file and print one line on stderr.

Forward lookup can show **A**, **AAAA**, **CNAME**, **MX**, **NS**, **TXT**, **SOA**, **CAA**, **HTTPS**, and **SVCB**. **SRV** is opt-in (`--srv`) and is not queried at the apex. `--reverse` maps an IP to a hostname via **PTR**. Missing PTR is common and is not a vulnerability.

`--record A` **queries only A**. `--record MX` still queries **A first** (existence); JSON/CSV therefore include that A plus MX — collected data, not a hidden full-zone dump.

### Multiple resolvers

Copy `config/resolvers.example.json` to `config/resolvers.json` (gitignored) and replace placeholder IPs with recursive resolvers you are allowed to query. The example uses `203.0.113.53` (documentation address, RFC 5737). The program does **not** ship Google/Cloudflare addresses in code.

Empty `nameservers` means the OS list. Optional `delay_seconds` (0–10) pauses between extra resolvers.

Different A/AAAA answers are labeled *Potential DNS inconsistency*. That can be geo-DNS, anycast, cache lag, or split-horizon — **not** proof of hijacking. Extra resolver timeouts do not abort the scan (`INCOMPLETE`). Comparison does not change the risk score.

---

## CLI Examples

Human report (default = `--all`):

```bash
python main.py example.com
```

One record type (no security sections, no extra type queries except A for existence):

```bash
python main.py example.com --record MX
```

HTTPS service binding (DNS type 65, not an HTTP request):

```bash
python main.py example.com --record HTTPS
```

Security sections only:

```bash
python main.py example.com --security
```

One DKIM selector (from a mail header, not guessed):

```bash
python main.py example.com --dkim google
```

One SRV service (name from the application, not guessed):

```bash
python main.py example.com --srv sip
python main.py example.com --srv sip/udp
```

JSON on stdout (pipe-friendly; no “DNS ANALYZER” banner):

```bash
python main.py example.com --format json
```

HTML file (open in a browser; no JavaScript):

```bash
python main.py example.com --format html --output reports/example_com.html
```

Human report plus a JSON file:

```bash
python main.py example.com --output reports/example_com.json
```

Reverse DNS:

```bash
python main.py --reverse 8.8.8.8
```

Compare two recursive resolvers (after you edit the example IPs):

```bash
python main.py example.com --config config/resolvers.json --resolver system --resolver secondary
```

```bash
python main.py --help
```

---

## JSON / CSV / HTML

JSON and CSV are for other programs, not for humans scraping the terminal. HTML is a printable page for people.

- **`--format json`** — JSON on stdout (no CLI dump). Pipe into `jq` or another tool.
- **`--format html`** — self-contained HTML on stdout (no CLI dump). Prefer `--output file.html`.
- **`--output file.json`** — write the file; default text mode still prints the human report.
- **CSV** — one row per record (`record_type,name,value,ttl,priority`). Findings and the risk score are JSON/HTML, not CSV.

HTML uses inline CSS only: no JavaScript, no CDN. Record values are escaped (`&lt;script&gt;`) so a TXT string cannot inject markup.

JSON includes `schema` (`dns-analyzer.report.v1`), `tool_version`, `target`, `scan_time` (UTC ISO 8601), `duration_ms`, `records`, `errors`, `dnssec`, `spf`, `dmarc`, `mta_sts`, `tls_rpt`, `bimi`, `tlsa`, `sshfp`, `fcrdns` and `mx_hosts` (when security view is on), `dkim` (only when `--dkim` is used), `srv` (only when `--srv` is used), `security_analysis` (findings), and `risk_score` (with contributions). `--config` with two or more resolvers adds `resolver_comparison`.

`scan_time` is UTC. `duration_ms` covers DNS queries for that run, including extra resolvers when comparison is on, not JSON encoding. The risk object is the same heuristic as the CLI, not CVSS.

---

## Logging

Each real analysis writes diagnostics to `logs/dns-analyzer.log` (gitignored, rotating, 1 MB × 3 backups).

Typical lines:

```
INFO  DNS analysis started target=example.com mode=forward resolver=system
INFO  Querying A record for example.com
WARNING  DNS query timeout for CAA example.com
ERROR  Invalid domain
```

Logs are **not** the user interface. They do not go to stdout, so `--format json` stays pipe-clean. Record values (A addresses, TXT tokens, SPF strings) are not written — only the name, type, and count. Do not paste log files that might contain internal hostnames into a public gist without review.

---

## Security Analysis

After records and policy sections, the CLI prints **SECURITY ANALYSIS**. Each finding has a severity (`info` / `low` / `medium`), a title, a description, a recommendation, and a `code` (JSON).

This engine **does not assign CVEs**. Missing DNSSEC, SPF, DMARC, or CAA is a configuration signal. `p=none` is a weak/monitor policy, not a critical hole. `+all` and multiple SPF/DMARC records are treated as configuration issues. A private or loopback A/AAAA on a name is flagged as likely misconfiguration, not proof of a breach. A CNAME with no A/AAAA in this resolver view is a possible dangling alias — not an automatic takeover. A TXT timeout is **not** scored as “SPF missing”.

### Risk score

The CLI prints **RISK SCORE** after findings. The number is **0–100**; higher means more concern **in this tool only**.

| Score | Band |
| --- | --- |
| 0–20 | LOW |
| 21–50 | MEDIUM |
| 51–75 | HIGH |
| 76–100 | CRITICAL |

This is **not CVSS**, not a NIST/ISO grade, and not a probability that the domain is compromised. Each point is listed as a contribution so you can see the math.

Examples from the current weights:

- Missing DMARC: **+10**
- Weak DMARC (`p=none`): **+5**
- DNSSEC not detected: **+5** (intentionally small — many resolvers hide DNSSEC)
- SPF `+all`: **+22**
- Missing CAA: **+2**
- TXT timeout: **+0** (unread is not treated as missing)

A clean published set (DNSSEC visible, SPF `-all`, DMARC `p=reject`, CAA present, public A) scores **0**. Resolver comparison never adds points. A DKIM selector or SRV service you asked for and that is missing scores **+0**. An empty DKIM `p=` (revoked key) scores **+8**.

---

## DNSSEC

DNSSEC signs DNS data so a **validating resolver** can check integrity (the answer was not altered in transit) and authenticity (it came from the signed zone). It is a defense against **DNS spoofing**, not a proof that a website is safe.

This tool reports:

- **DNSKEY** — the zone publishes signing keys
- **DS** — the parent zone has a hash of those keys (chain toward the root)
- **AD flag** — whether *your* recursive resolver marked the answer as authenticated

`DETECTED` means those signals were visible **to this resolver**. It is **not** a full validation against the IANA root key. `NOT DETECTED` does not mean the domain is compromised — many ISP resolvers hide DNSSEC records or never set AD.

---

## SPF / DKIM / DMARC

These are **email authentication** signals in DNS. They do not encrypt mail. Absence is a configuration observation, not a CVE.

**SPF** (Sender Policy Framework) is a TXT record starting with `v=spf1`. Receiving mail servers use it to check whether the connecting host is allowed to send mail that claims this domain.

- `-all` — fail (reject unauthorized senders)
- `~all` — softfail (often still delivered, sometimes marked)
- `+all` — pass everyone (unusual)

RFC 7208 expects **one** `v=spf1` record at the name. `include:` and `redirect=` are followed **one hop** (at most 10 names). Nested `include:` is listed, not queried. `a`, `mx`, `ptr`, and `exists` are not evaluated. This is not a full SPF check for a sending IP.

**DKIM** (DomainKeys Identified Mail) uses a TXT record at a **selector** name, for example `google._domainkey.example.com`. The selector is chosen by the sender (see the `s=` tag in a `DKIM-Signature` mail header). This tool looks up selectors only when you pass `--dkim SELECTOR`. It does **not** brute-force `google`, `s1`, `default`, or any other list.

```bash
python main.py example.com --dkim google --dkim s1
```

`FOUND` means that selector published `v=DKIM1` with a non-empty `p=`. Empty `p=` is **revoked**. NXDOMAIN / no DKIM TXT is **NOT DETECTED** for that selector only — other selectors may still exist. Timeout is unread, not “DKIM missing”. The CLI prints key type and key length, not the raw public key.

**DMARC** is a TXT record at `_dmarc.example.com` (`v=DMARC1`). It tells receivers what to do when mail is not aligned with SPF and/or DKIM.

- **p=none** — monitor only; delivery is not changed
- **p=quarantine** — typically treat failing mail as spam
- **p=reject** — reject failing mail

Missing DMARC is an observation, not an automatic critical vulnerability. Multiple `v=DMARC1` records are a configuration problem (receivers may ignore DMARC).

**MTA-STS** (RFC 8461) tells sending MTAs to use TLS to this domain according to a policy file. This tool only reads the DNS id: TXT at `_mta-sts.example.com` (`v=STSv1; id=...`). The policy itself lives at `https://mta-sts.example.com/.well-known/mta-sts.txt` and is **not fetched**. Missing MTA-STS is common; it does not mean SMTP is unencrypted. This is not a STARTTLS scanner.

**TLS-RPT** (RFC 8460) is the reporting half: TXT at `_smtp._tls.example.com` (`v=TLSRPTv1; rua=mailto:...` or `https:`). Senders can mail JSON reports about TLS failures. The `rua=` address is shown; this tool does not send SMTP or fetch HTTPS report URLs. Missing TLS-RPT is common and is not a compromise.

**BIMI** (RFC 9091) publishes a brand logo URL so some inboxes can show a mark on aligned mail. This tool only queries the well-known selector `default`: TXT at `default._bimi.example.com` (`v=BIMI1; l=https://...; a=https://...`). The `l=` SVG and `a=` VMC/evidence URLs are shown, not fetched. Other selectors are not guessed. Inboxes typically also require DMARC `p=quarantine` or `p=reject`. Missing BIMI is common and is not a compromise. BIMI is not a certificate of authenticity by itself.

**DANE / TLSA** (RFC 6698) publishes a certificate association in DNS so a TLS client can check a server certificate without (or in addition to) the public CA system. This tool only queries `_443._tcp.<domain>` (HTTPS, port 443). It does **not** open TCP/443, does not follow MX hosts, and does not compare the live certificate. Usage `3` (DANE-EE) plus selector `1` (SPKI) and matching `1` (SHA-256) is the usual “this key in DNS” shape. Missing TLSA is common; most sites still rely on CAs only. `--record TLSA` is rejected because TLSA is not at the apex.

**SSHFP** (RFC 4255) publishes SSH host-key fingerprints at the hostname itself (`4 2 <sha256>` is Ed25519 + SHA-256). OpenSSH can use this with `VerifyHostKeyDNS` when DNSSEC validates. This tool only reads the DNS record. It does **not** open TCP/22 or compare live host keys. Missing SSHFP is common for names that are not SSH servers.

**MX hosts** are names, not IP addresses. After the MX RRset, this tool looks up A/AAAA for up to 8 targets. It does **not** open TCP/25 or speak SMTP. `RESOLVES` means the host has an address. `NO ADDRESS` / `NXDOMAIN` means mail may bounce. RFC 7505 **null MX** (exchange `.`) means this name does not accept mail — that is a published policy, not a missing host. Missing MX is common for names that are not mail domains.

---

## SRV

**SRV** (RFC 2782) maps a **service name** to a host and port. The record lives at `_service._proto.<domain>`, not at the apex. This tool looks up services only when you pass `--srv SERVICE`. It does **not** brute-force `sip`, `xmpp`, `minecraft`, or any other list.

```bash
python main.py example.com --srv sip --srv xmpp/tcp
```

Default protocol is **tcp**. Use `sip/udp` for UDP. `FOUND` lists priority (lowest first), weight, port, and target. Target `.` means this service is not offered at this name. NXDOMAIN / empty is **NOT DETECTED** for that service only. Timeout is unread, not “SRV missing”. `--record SRV` is rejected; use `--srv`.

---

## CAA

**CAA** (Certification Authority Authorization) says which CAs may issue certificates for the name (`issue` / `issuewild` / `iodef`).

No CAA record is common. CAs may look at parent names. Absence is a **low-weight** observation here, not “the domain is hijacked”. This tool does not talk to CAs or check CT logs.

**HTTPS** and **SVCB** (RFC 9460) are separate DNS types. They tell a client which protocols, ports, or Encrypted Client Hello (ECH) config this name advertises. A missing HTTPS record is not “the site is down”. This tool does not fetch web pages.

---

## Reverse DNS

`python main.py --reverse 8.8.8.8` does **not** contact 8.8.8.8. It queries `8.8.8.8.in-addr.arpa` (or `ip6.arpa` for IPv6) for a **PTR** record. Forward (name → IP) and reverse (IP → name) are separate zones; they do not have to match.

Default / `--security` also runs **FCrDNS** on up to 8 A/AAAA addresses: PTR, then A or AAAA of that PTR name. `CONFIRMED` means the circle closed. `NO PTR` is common. `MISMATCH` is not hijacking. The IP is never contacted.

`--reverse` uses the primary resolver only (OS, `--nameserver`, or the first profile in `--config`). It does not compare PTR across extra resolvers.

---

## Architecture

```
dns-analyzer/
├── main.py                      # thin entry: sys.exit(run())
├── CHANGELOG.md
├── requirements.txt
├── config/resolvers.example.json
├── analyzer/                    # DNS + security logic (no printing)
│   ├── version.py               # __version__
│   ├── validator.py             # URL / domain normalization
│   ├── resolver.py              # dnspython wrapper, lookup_core
│   ├── records.py               # rdata → DNSRecord
│   ├── models.py                # DNSRecord, CoreLookup
│   ├── reverse.py               # IP → PTR name
│   ├── ttl.py                   # cache-lifetime wording
│   ├── dnssec.py / spf.py / dmarc.py / dkim.py / srv.py / mtasts.py / tlsrpt.py / bimi.py / tlsa.py / sshfp.py / fcrdns.py / mx.py
│   ├── security.py / risk.py
│   ├── config.py / compare.py   # named resolvers, A/AAAA diff
│   └── result.py                # one run, ready to export
├── cli/interface.py             # argparse, human output, exit codes
├── utils/logger.py              # rotating file log
├── utils/reporter.py            # JSON / CSV / HTML
├── reports/                     # generated files (gitignored)
├── logs/                        # application logs (gitignored)
└── tests/                       # pytest, mocked DNS
```

`analyzer/` does not print. `cli/` does not own the wire format of DNS. That split keeps the core testable and leaves a GUI as a later consumer of the same types.

---

## Testing

```bash
python -m pytest -q
```

Tests do **not** contact real nameservers. `dnspython` is mocked. Validator, TTL, SPF, DMARC, DKIM, SRV, MTA-STS, TLS-RPT, BIMI, DANE TLSA, SSHFP, FCrDNS, MX hosts, CAA formatting, DNSSEC evaluation, risk weights, JSON/CSV/HTML, CLI flags, logging, config loading, and resolver comparison are all local.

If a test needs the network, it does not belong in this suite.

---

## Limitations

- Not a vulnerability scanner
- Absence of DNSSEC / SPF / DMARC / CAA is a signal, not automatic critical risk
- Missing HTTPS/SVCB is common and is not scored
- DNSSEC here is **visibility to this resolver**, not validation to the IANA root
- SPF `include:` / `redirect=` are followed one hop; nested include: and a/mx/ptr/exists are not evaluated
- DKIM selectors are **opt-in** (`--dkim`); they are never brute-forced or guessed
- SRV services are **opt-in** (`--srv`); they are never brute-forced or guessed
- MTA-STS is DNS-only (`_mta-sts` TXT); the HTTPS policy file is not fetched
- TLS-RPT is DNS-only (`_smtp._tls` TXT); SMTP is not probed and HTTPS rua URLs are not fetched
- BIMI is DNS-only (`default._bimi` TXT); only the default selector is queried; logo and VMC URLs are not fetched
- DANE TLSA is DNS-only (`_443._tcp`); TLS is not probed and MX hosts are not followed
- SSHFP is DNS-only (at the hostname); SSH is not probed
- FCrDNS is DNS-only (PTR then forward A/AAAA); the IP is not contacted; mismatch is not hijacking
- MX host lookup is DNS-only (A/AAAA of the MX target); SMTP is not probed; missing MX is not a compromise
- Documentation addresses (`192.0.2.0/24`, `2001:db8::/32`, …) are labeled, not scored as private LAN
- The risk score is a local heuristic, not a security standard
- Different answers from two resolvers are not proof of hijacking
- Results must be interpreted in context
- Subdomain enumeration is out of v1 and, if added later, is for authorized domains only

---

## Responsible Use

Only analyze domains you own or have permission to test. Public recursive lookups (`dig`-style) are how DNS is meant to be queried; do not use future enumeration features against third-party infrastructure. Do not treat this report as a penetration-test finding list.

---

## Roadmap

**v1.12.0** adds MX host address lookup. History: [CHANGELOG.md](CHANGELOG.md).

Possible later work (not scheduled): GUI on the same `analyzer/` types, authorized subdomain discovery, WHOIS, PDF. Enumeration, if added, stays opt-in and for domains you are allowed to test.

---

## License

MIT — see [LICENSE](LICENSE).
