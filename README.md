# DNS Analyzer

Professional DNS analysis CLI for learning DNS, DNS security signals, and network behavior.

> **Current status:** Phase 4 — A (IPv4) and AAAA (IPv6) records.

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
- Optional risk score (transparent, non-standard)
- JSON / CSV reports
- Logging and unit tests with mocks

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
python main.py https://example.com/login
python main.py example.com --timeout 3
python main.py --help
```

Phase 4 validates the input, then queries **A** (IPv4) and **AAAA** (IPv6) records. A missing AAAA record is displayed as an observation, not an error.

Invalid input or DNS failures (NXDOMAIN, timeout) exit with code 1 and a clear error.

## DNS Record Types (so far)

| Type | Meaning | Missing means |
| --- | --- | --- |
| **A** | Hostname → IPv4 address | This name has no IPv4 mapping (it may still have AAAA) |
| **AAAA** | Hostname → IPv6 address | This name has no IPv6 mapping (very common; not a vulnerability) |

TTL is shown next to each record. It is a cache lifetime, not a security score.

## Testing

```bash
python -m pytest tests/ -q
```

Validator, record-formatting, and resolver tests do not contact real nameservers. Resolver tests mock `dnspython`.

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
- Results must be interpreted in context
- Subdomain enumeration (future) is for authorized domains only

---

## Responsible Use

Only analyze domains you own or have permission to test. Do not use enumeration features against third-party infrastructure.

---

## Roadmap

See the phase plan in the project brief. Next: **Phase 5 — CNAME / MX / NS records**.

## License

MIT — see [LICENSE](LICENSE).
