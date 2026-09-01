"""Core DNS analysis package.

Modules (filled in later phases):
- validator: accept a domain, reject or normalize bad input
- resolver:  send DNS queries through dnspython
- records:   parse A, AAAA, MX, NS, TXT, SOA, CAA, PTR, CNAME
- security:  DNSSEC / SPF / DMARC / CAA findings
- models:    dataclasses for records and analysis results
"""
