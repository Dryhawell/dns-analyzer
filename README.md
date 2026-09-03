# DNS Analyzer

Professional DNS analysis CLI for learning DNS, DNS security signals, and network behavior.

> **Current status:** Phase 19 — query only needed record types; remaining types after A may run in parallel.

This is **not** a vulnerability scanner. Missing records (DNSSEC, SPF, DMARC, CAA) are observations, not automatic proof of compromise.

---

## Overview

DNS Analyzer takes a domain (`example.com`) and will eventually:

1. Validate and normalize the input
2. Query DNS record types (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, PTR)
3. Inspect security-related signals (DNSSEC, SPF, DMARC, CAA)
4. Produce a readable CLI report plus JSON/CSV export

Three layers:

| Layer | What it answers |
| --- | --- |
| DNS Records | How is this name published on the internet? |
| DNS Security | Which email / authenticity / certificate policies are visible? |
| Network | How do resolvers, TTL, caching, and reverse DNS behave? |

---

## Features (planned)

- Domain validation and URL → domain normalization
- Record lookup via dnspython
- TTL display (not scored as secure/insecure)
- DNSSEC detection as a finding, not a verdict
- SPF / DMARC parsing from TXT records
- CAA inspection
- Reverse DNS (`PTR`)
- Security findings with severity, description, recommendation
- Transparent risk score (local heuristic; not CVSS)
- JSON / CSV reports
- File logging (`logs/dns-analyzer.log`; no secrets or rdata)
- Unit tests with mocks

**Not in v1:** GUI, aggressive subdomain brute-force, WHOIS, geolocation, HTML/PDF reports.

---

## Why DNS Security Matters

DNS maps names to infrastructure. If that mapping is spoofed, hijacked, or weakly configured, users and mail can be sent to the wrong place. This tool teaches you to **read** DNS, not to declare every missing record a CVE.

---

## Installation

Python 3.12+

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

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
python main.py --reverse 8.8.8.8 --format json
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

Forward lookup can show **A**, **AAAA**, **CNAME**, **MX**, **NS**, **TXT**, **SOA**, and **CAA**. `--reverse` maps an IP to a hostname via **PTR**. Missing PTR is common and is not a vulnerability.

JSON includes `schema` (`dns-analyzer.report.v1`), `target`, `scan_time` (UTC ISO 8601), `duration_ms`, `records`, `errors`, `dnssec`, `spf`, `dmarc`, `security_analysis` (findings), and `risk_score` (with contributions). CSV is a flat table: `record_type,name,value,ttl,priority`. `--record A` **queries only A** (existence check is A itself); JSON/CSV contain collected records, not hidden extras.

Invalid input or DNS failures (NXDOMAIN on a domain, timeout, network error) exit with code 1 and a clear message. The program does not print a traceback for those cases. Ctrl+C exits 130 (`Interrupted.`). `--timeout` must be between 0 (exclusive) and 120 seconds.

## DNS Record Types (so far)

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

## TTL, caching, and propagation

TTL (Time To Live) is how long a resolver may reuse an answer without asking again.

- **Low TTL** — a change (new A record, new MX) becomes visible sooner. Resolvers also query more often.
- **High TTL** — less query load, but after you change a record some users keep the old answer until their cache expires. That delay is what people call **DNS propagation**. It is not a global countdown; each resolver has its own remaining TTL.

A 60-second A record is not "insecure". An 86400-second NS record is not "secure". They are operational choices.

## DNSSEC

DNSSEC signs DNS data so a **validating resolver** can check integrity (the answer was not altered in transit) and authenticity (it came from the signed zone). It is a defense against **DNS spoofing**, not a proof that a website is safe.

This tool reports:

- **DNSKEY** — the zone publishes signing keys
- **DS** — the parent zone has a hash of those keys (chain toward the root)
- **AD flag** — whether *your* recursive resolver marked the answer as authenticated

`DETECTED` means those signals were visible **to this resolver**. It is **not** a full validation against the IANA root key. `NOT DETECTED` does not mean the domain is compromised — many ISP resolvers hide DNSSEC records.

## SPF

SPF (Sender Policy Framework) is a TXT record starting with `v=spf1`. Receiving mail servers use it to check whether the connecting host is allowed to send mail that claims this domain.

- `-all` — fail (reject unauthorized senders)
- `~all` — softfail (often still delivered, sometimes marked)
- `+all` — pass everyone (unusual)

`NOT DETECTED` is not an automatic critical finding. This tool does not follow `include:` chains.

## DMARC

DMARC is a TXT record at `_dmarc.example.com` (`v=DMARC1`). It tells receivers what to do when mail is not aligned with SPF and/or DKIM.

- **p=none** — monitor only; delivery is not changed
- **p=quarantine** — typically treat failing mail as spam
- **p=reject** — reject failing mail

Missing DMARC is an observation, not an automatic critical vulnerability. DKIM needs a selector (`google._domainkey.example.com`) and is not auto-discovered in v1.

## Security analysis

After records and policy sections, the CLI prints **SECURITY ANALYSIS**. Each finding has a severity (`info` / `low` / `medium`), a title, a description, and a recommendation.

This engine **does not assign CVEs**. Missing DNSSEC, SPF, DMARC, or CAA is a configuration signal. `p=none` is a weak/monitor policy, not a critical hole. `+all` and multiple SPF/DMARC records are treated as configuration issues. A private or loopback A/AAAA on a name is flagged as likely misconfiguration, not proof of a breach. A CNAME with no A/AAAA in this resolver view is a possible dangling alias — not an automatic takeover.

## Risk score

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
- TXT timeout: **+0** (unread is not treated as missing)

A clean published set (DNSSEC visible, SPF `-all`, DMARC `p=reject`, CAA present, public A) scores **0**.

## JSON / CSV

Reports are for other programs, not for humans scraping the terminal.

```bash
python main.py example.com --format json
python main.py example.com --output reports/example_com.json
```

- **`--format json`** — JSON on stdout (no CLI dump). Pipe into `jq` or another tool.
- **`--output file.json`** — write the file; default text mode still prints the human report.
- **CSV** — one row per record (`record_type,name,value,ttl,priority`). Findings and the risk score are JSON-only.

`scan_time` is UTC. `duration_ms` covers DNS queries for that run, not JSON encoding. The risk object is the same heuristic as the CLI, not CVSS.

## Logging

Each real analysis writes diagnostics to `logs/dns-analyzer.log` (gitignored, rotating, 1 MB × 3 backups).

Typical lines:

```
INFO  DNS analysis started target=example.com
INFO  Querying A record for example.com
WARNING  DNS query timeout for CAA example.com
ERROR  Invalid domain
```

Logs are **not** the user interface. They do not go to stdout, so `--format json` stays pipe-clean. Record values (A addresses, TXT tokens, SPF strings) are not written — only the name, type, and count. Do not paste log files that might contain internal hostnames into a public gist without review.

## Reverse DNS

`python main.py --reverse 8.8.8.8` does **not** contact 8.8.8.8. It queries `8.8.8.8.in-addr.arpa` for a PTR record. Forward (name → IP) and reverse (IP → name) are separate zones; they do not have to match.

## Testing

```bash
python -m pytest tests/ -q
```

Tests do **not** contact real nameservers. `dnspython` is mocked; validator, TTL, SPF, DMARC, CAA formatting, DNSSEC evaluation, risk weights, JSON/CSV, CLI flags, and logging are all local.

Covered (among others): valid/invalid domains, record parsing, TTL, SPF/DMARC/CAA/DNSSEC, risk score, JSON export, NXDOMAIN/timeout CLI exits.

If a test needs the network, it does not belong in this suite.

---

## Architecture

```
dns-analyzer/
├── main.py              # thin entry point
├── analyzer/            # DNS + security logic
├── cli/                 # argparse and terminal output
├── utils/               # logging and reporting
├── reports/             # generated JSON/CSV (gitignored)
├── logs/                # application logs (gitignored)
└── tests/               # pytest, mocked DNS
```

`analyzer/` does not print. `cli/` does not query DNS. That split keeps the core testable and GUI-ready later.

---

## Limitations

- Not a vulnerability scanner
- Absence of DNSSEC / SPF / DMARC / CAA is a signal, not automatic critical risk
- The risk score is a local heuristic, not a security standard
- Results must be interpreted in context
- Subdomain enumeration (future) is for authorized domains only

---

## Responsible Use

Only analyze domains you own or have permission to test. Do not use enumeration features against third-party infrastructure.

---

## Roadmap

See the phase plan in the project brief. Next: **Phase 20 — Optional multi-resolver (config, no hardcoded IPs)**.

## License

MIT — see [LICENSE](LICENSE).
