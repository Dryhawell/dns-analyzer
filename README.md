# DNS Analyzer

Professional DNS analysis CLI: it reads how a name is published, interprets security-related DNS signals, and writes a report you can share or pipe to other tools.

> **Current status:** **v1.0.0** — see [CHANGELOG.md](CHANGELOG.md).

This is **not** a vulnerability scanner. Missing records (DNSSEC, SPF, DMARC, CAA) are observations, not automatic proof of compromise.

---

## Overview

DNS Analyzer takes a domain (`example.com` or a URL) or an IP (`--reverse`) and:

1. Validates and normalizes the input
2. Queries selected DNS record types (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, PTR)
3. Inspects security-related signals (DNSSEC, SPF, DMARC, CAA)
4. Prints a readable CLI report and can export JSON or CSV

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
- SPF and DMARC parsing from TXT; DKIM is explained, not auto-discovered
- CAA inspection
- Reverse DNS (`PTR`)
- Security findings with severity, description, recommendation, and a stable `code`
- Transparent risk score (local heuristic, 0–100; not CVSS)
- JSON (`dns-analyzer.report.v1`) and CSV export
- Optional multi-resolver A/AAAA comparison from a JSON config (no hardcoded public DNS IPs)
- File logging (`logs/dns-analyzer.log`; no secrets or rdata values)
- Unit tests with mocks (no live nameservers)

**Not in v1:** GUI, aggressive subdomain brute-force, WHOIS, geolocation, HTML/PDF reports, DKIM selector hunting.

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
| **PTR** | IP → hostname (reverse DNS, under in-addr.arpa / ip6.arpa) | The address has no published reverse name |

TTL is shown next to each record as a **cache lifetime**, never as a security score. MX **priority**: lower number is tried first.

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
python main.py example.com --security
python main.py https://example.com/login
python main.py example.com --timeout 3
python main.py example.com --format json
python main.py example.com --output reports/example_com.json
python main.py example.com --format csv --output reports/example_com.csv
python main.py example.com --config config/resolvers.example.json
python main.py example.com --nameserver 192.0.2.53
python main.py --reverse 8.8.8.8 --format json
python main.py --version
```

| Mode | What you get |
| --- | --- |
| (default) or `--all` | Every core record type, TTL summary, DNSSEC, SPF, DMARC, findings, risk score |
| `--record TYPE` | Only that type (repeatable). Skips security queries. Other types are not queried; **A is still queried first** so NXDOMAIN can abort |
| `--security` | DNSSEC / SPF / DMARC / findings / score, without the record dump. Queries A, AAAA, CNAME, TXT, CAA (not MX/NS/SOA) |
| `--record A --security` | That type plus the security sections |
| `--reverse IP` | PTR only |
| `--format json` / `csv` | Machine-readable stdout (no human dump) |
| `--output PATH` | Write `.json` or `.csv`; with default text mode the human report still prints |
| `--config PATH` | Named recursive resolvers from JSON. Two or more compare **A/AAAA** |
| `--resolver NAME` | Pick names from `--config` (repeatable). First is the primary scan |
| `--nameserver IP` | Use this recursive resolver instead of the OS list (repeatable). Not combined with `--config` |
| `--version` | Print `dns-analyzer 1.0.0` and exit |

`--timeout` must be between 0 (exclusive) and 120 seconds. Default is 5. Each nameserver waits that long; **lifetime** is timeout × (up to 4 nameservers) so a dead first recursive server can fail over.

| Exit code | Meaning |
| --- | --- |
| **0** | Success (including “no PTR found” on reverse) |
| **1** | Invalid input, DNS/network failure, or could not write a report |
| **130** | Interrupted (Ctrl+C) |

The program does not print a traceback for expected DNS or CLI errors. Unexpected failures log a traceback to the log file and print one line on stderr.

Forward lookup can show **A**, **AAAA**, **CNAME**, **MX**, **NS**, **TXT**, **SOA**, and **CAA**. `--reverse` maps an IP to a hostname via **PTR**. Missing PTR is common and is not a vulnerability.

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

Security sections only:

```bash
python main.py example.com --security
```

JSON on stdout (pipe-friendly; no “DNS ANALYZER” banner):

```bash
python main.py example.com --format json
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

## JSON / CSV

Reports are for other programs, not for humans scraping the terminal.

- **`--format json`** — JSON on stdout (no CLI dump). Pipe into `jq` or another tool.
- **`--output file.json`** — write the file; default text mode still prints the human report.
- **CSV** — one row per record (`record_type,name,value,ttl,priority`). Findings and the risk score are JSON-only.

JSON includes `schema` (`dns-analyzer.report.v1`), `tool_version`, `target`, `scan_time` (UTC ISO 8601), `duration_ms`, `records`, `errors`, `dnssec`, `spf`, `dmarc`, `security_analysis` (findings), and `risk_score` (with contributions). `--config` with two or more resolvers adds `resolver_comparison`.

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

A clean published set (DNSSEC visible, SPF `-all`, DMARC `p=reject`, CAA present, public A) scores **0**. Resolver comparison never adds points.

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

RFC 7208 expects **one** `v=spf1` record at the name. This tool does not follow `include:` chains.

**DKIM** (DomainKeys Identified Mail) uses a TXT record at a **selector** name, for example `google._domainkey.example.com`. The selector is chosen by the sender; this tool does **not** guess selectors in v1. DMARC still refers to DKIM alignment when mail is checked.

**DMARC** is a TXT record at `_dmarc.example.com` (`v=DMARC1`). It tells receivers what to do when mail is not aligned with SPF and/or DKIM.

- **p=none** — monitor only; delivery is not changed
- **p=quarantine** — typically treat failing mail as spam
- **p=reject** — reject failing mail

Missing DMARC is an observation, not an automatic critical vulnerability. Multiple `v=DMARC1` records are a configuration problem (receivers may ignore DMARC).

---

## CAA

**CAA** (Certification Authority Authorization) says which CAs may issue certificates for the name (`issue` / `issuewild` / `iodef`).

No CAA record is common. CAs may look at parent names. Absence is a **low-weight** observation here, not “the domain is hijacked”. This tool does not talk to CAs or check CT logs.

---

## Reverse DNS

`python main.py --reverse 8.8.8.8` does **not** contact 8.8.8.8. It queries `8.8.8.8.in-addr.arpa` (or `ip6.arpa` for IPv6) for a **PTR** record. Forward (name → IP) and reverse (IP → name) are separate zones; they do not have to match.

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
│   ├── dnssec.py / spf.py / dmarc.py
│   ├── security.py / risk.py
│   ├── config.py / compare.py   # named resolvers, A/AAAA diff
│   └── result.py                # one run, ready to export
├── cli/interface.py             # argparse, human output, exit codes
├── utils/logger.py              # rotating file log
├── utils/reporter.py            # JSON / CSV
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

Tests do **not** contact real nameservers. `dnspython` is mocked. Validator, TTL, SPF, DMARC, CAA formatting, DNSSEC evaluation, risk weights, JSON/CSV, CLI flags, logging, config loading, and resolver comparison are all local.

If a test needs the network, it does not belong in this suite.

---

## Limitations

- Not a vulnerability scanner
- Absence of DNSSEC / SPF / DMARC / CAA is a signal, not automatic critical risk
- DNSSEC here is **visibility to this resolver**, not validation to the IANA root
- SPF `include:` chains are not followed; DKIM selectors are not discovered
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

**v1.0.0** is the first stable CLI. History: [CHANGELOG.md](CHANGELOG.md).

Possible later work (not scheduled): GUI on the same `analyzer/` types, authorized subdomain discovery, WHOIS, HTML/PDF reports. Enumeration, if added, stays opt-in and for domains you are allowed to test.

---

## License

MIT — see [LICENSE](LICENSE).
