"""CLI tests with a mocked resolver. No network access."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from analyzer.dmarc import evaluate_dmarc
from analyzer.dnssec import DnssecDelegation, DnssecKey, evaluate_dnssec
from analyzer.exceptions import DNSTimeoutError, DomainNotFoundError
from analyzer.models import CoreLookup, DNSRecord
from analyzer.bimi import evaluate_bimi
from analyzer.fcrdns import FcrdnsCheck, evaluate_fcrdns
from analyzer.mx import evaluate_mx_hosts
from analyzer.ns import evaluate_ns_hosts
from analyzer.cname import evaluate_cname_targets
from analyzer.soa import evaluate_soa_ns
from analyzer.caa import evaluate_caa
from analyzer.cds import CdnskeyRecord, CdsRecord, evaluate_cds
from analyzer.nsec import Nsec3ParamRecord, NsecRecord, evaluate_nsec
from analyzer.csync import CsyncRecord, evaluate_csync
from analyzer.zonemd import ZonemdRecord, evaluate_zonemd
from analyzer.rrsig import RrsigRecord, evaluate_rrsig
from analyzer.sshfp import evaluate_sshfp
from analyzer.tlsa import evaluate_tlsa
from analyzer.mtasts import evaluate_mta_sts
from analyzer.tlsrpt import evaluate_tls_rpt
from analyzer.version import __version__
from cli.interface import ExportPlan, ReportView, build_parser, plan_export, run, types_to_query


def _lookup(
    a: list[DNSRecord] | None = None,
    aaaa: list[DNSRecord] | None = None,
    cname: list[DNSRecord] | None = None,
    mx: list[DNSRecord] | None = None,
    ns: list[DNSRecord] | None = None,
    txt: list[DNSRecord] | None = None,
    soa: list[DNSRecord] | None = None,
    caa: list[DNSRecord] | None = None,
    https: list[DNSRecord] | None = None,
    svcb: list[DNSRecord] | None = None,
    errors: tuple[tuple[str, str], ...] = (),
) -> CoreLookup:
    return CoreLookup(
        a=tuple(a or []),
        aaaa=tuple(aaaa or []),
        cname=tuple(cname or []),
        mx=tuple(mx or []),
        ns=tuple(ns or []),
        txt=tuple(txt or []),
        soa=tuple(soa or []),
        caa=tuple(caa or []),
        https=tuple(https or []),
        svcb=tuple(svcb or []),
        errors=errors,
    )


def _dnssec(
    dnskey_found: bool = False,
    ds_found: bool = False,
    ad_flag: bool = False,
    keys=(),
    delegations=(),
):
    return evaluate_dnssec(
        dnskey_found=dnskey_found,
        ds_found=ds_found,
        ad_flag=ad_flag,
        keys=keys,
        delegations=delegations,
    )


def _dmarc(record: str | None = None) -> object:
    qname = "_dmarc.example.com"
    if record is None:
        return evaluate_dmarc(qname, ())
    return evaluate_dmarc(qname, [DNSRecord("TXT", qname, record, 300)])


def _mtasts(record: str | None = None) -> object:
    qname = "_mta-sts.example.com"
    host = "mta-sts.example.com"
    if record is None:
        return evaluate_mta_sts(qname, host, ())
    return evaluate_mta_sts(qname, host, [DNSRecord("TXT", qname, record, 300)])


def _tlsrpt(record: str | None = None) -> object:
    qname = "_smtp._tls.example.com"
    if record is None:
        return evaluate_tls_rpt(qname, ())
    return evaluate_tls_rpt(qname, [DNSRecord("TXT", qname, record, 300)])


def _bimi(record: str | None = None) -> object:
    qname = "default._bimi.example.com"
    if record is None:
        return evaluate_bimi(qname, "default", ())
    return evaluate_bimi(qname, "default", [DNSRecord("TXT", qname, record, 300)])


def _tlsa(value: str | None = None) -> object:
    qname = "_443._tcp.example.com"
    if value is None:
        return evaluate_tlsa(qname, ())
    assoc = value.split()[-1] if value.split() else ""
    parts = value.split()
    return evaluate_tlsa(
        qname,
        [
            DNSRecord(
                "TLSA",
                qname,
                value,
                300,
                details=(
                    ("Usage", f"{parts[0]} — DANE-EE"),
                    ("Selector", f"{parts[1]} — SPKI"),
                    ("Matching", f"{parts[2]} — SHA-256"),
                    ("Association", assoc),
                ),
            )
        ],
    )


def _sshfp(value: str | None = None) -> object:
    qname = "example.com"
    if value is None:
        return evaluate_sshfp(qname, ())
    parts = value.split()
    fp = parts[2] if len(parts) > 2 else ""
    return evaluate_sshfp(
        qname,
        [
            DNSRecord(
                "SSHFP",
                qname,
                value,
                300,
                details=(
                    ("Algorithm", f"{parts[0]} — Ed25519"),
                    ("Fingerprint type", f"{parts[1]} — SHA-256"),
                    ("Fingerprint", fp),
                ),
            )
        ],
    )


def _fcrdns(*checks: FcrdnsCheck) -> object:
    return evaluate_fcrdns(checks)


def _mx_hosts(*checks) -> object:
    return evaluate_mx_hosts("example.com", checks)


def _ns_hosts(*checks) -> object:
    return evaluate_ns_hosts("example.com", checks)


def _cname_targets(*checks) -> object:
    return evaluate_cname_targets(checks)


def _soa_ns() -> object:
    return evaluate_soa_ns("example.com", None, ())


def _caa() -> object:
    return evaluate_caa("example.com", ())


def _cds() -> object:
    return evaluate_cds("example.com", cds_found=False, cdnskey_found=False)


def _nsec() -> object:
    return evaluate_nsec("example.com", nsec_found=False, nsec3param_found=False)


def _csync() -> object:
    return evaluate_csync("example.com", found=False)


def _zonemd() -> object:
    return evaluate_zonemd("example.com", found=False)


def _rrsig() -> object:
    return evaluate_rrsig("example.com", found=False)


def _bind(
    mock_cls,
    lookup: CoreLookup,
    dnssec=None,
    dmarc=None,
    mtasts=None,
    tlsrpt=None,
    bimi=None,
    tlsa=None,
    sshfp=None,
    fcrdns=None,
    mx_hosts=None,
    ns_hosts=None,
    cname_targets=None,
    soa_ns=None,
    caa=None,
    cds=None,
    nsec=None,
    csync=None,
    zonemd=None,
    rrsig=None,
) -> None:
    mock_cls.return_value.lookup_core.return_value = lookup
    mock_cls.return_value.inspect_dnssec.return_value = dnssec or _dnssec()
    mock_cls.return_value.inspect_dmarc.return_value = dmarc or _dmarc()
    mock_cls.return_value.inspect_mta_sts.return_value = mtasts or _mtasts()
    mock_cls.return_value.inspect_tls_rpt.return_value = tlsrpt or _tlsrpt()
    mock_cls.return_value.inspect_bimi.return_value = bimi or _bimi()
    mock_cls.return_value.inspect_tlsa.return_value = tlsa or _tlsa()
    mock_cls.return_value.inspect_sshfp.return_value = sshfp or _sshfp()
    mock_cls.return_value.inspect_fcrdns.return_value = fcrdns or _fcrdns()
    mock_cls.return_value.inspect_mx_hosts.return_value = mx_hosts or _mx_hosts()
    mock_cls.return_value.inspect_ns_hosts.return_value = ns_hosts or _ns_hosts()
    mock_cls.return_value.inspect_cname_targets.return_value = (
        cname_targets or _cname_targets()
    )
    mock_cls.return_value.inspect_soa_ns.return_value = soa_ns or _soa_ns()
    mock_cls.return_value.inspect_caa.return_value = caa or _caa()
    mock_cls.return_value.inspect_cds.return_value = cds or _cds()
    mock_cls.return_value.inspect_nsec.return_value = nsec or _nsec()
    mock_cls.return_value.inspect_csync.return_value = csync or _csync()
    mock_cls.return_value.inspect_zonemd.return_value = zonemd or _zonemd()
    mock_cls.return_value.inspect_rrsig.return_value = rrsig or _rrsig()
    mock_cls.return_value.expand_spf.side_effect = lambda obs: obs


@patch("cli.interface.DNSResolver")
def test_cli_prints_a_and_aaaa(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            a=[DNSRecord("A", "example.com", "93.184.216.34", 3600)],
            aaaa=[DNSRecord("AAAA", "example.com", "2001:db8::1", 300)],
        ),
    )

    assert run(["example.com"]) == 0
    mock_resolver_cls.return_value.lookup_core.assert_called_once_with(
        "example.com", types=None
    )
    mock_resolver_cls.return_value.inspect_dkim.assert_not_called()
    mock_resolver_cls.return_value.inspect_srv.assert_not_called()
    mock_resolver_cls.return_value.inspect_naptr.assert_not_called()
    mock_resolver_cls.return_value.inspect_uri.assert_not_called()
    mock_resolver_cls.return_value.inspect_dname.assert_not_called()
    mock_resolver_cls.return_value.inspect_ipseckey.assert_not_called()
    mock_resolver_cls.return_value.inspect_smimea.assert_not_called()
    mock_resolver_cls.return_value.inspect_cds.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_nsec.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_csync.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_zonemd.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_rrsig.assert_called_once_with("example.com")
    output = capsys.readouterr().out
    assert "Target:" in output
    assert "example.com" in output
    assert "A RECORDS" in output
    assert "93.184.216.34" in output
    assert "TTL: 3600s (1h)" in output
    assert "AAAA RECORDS" in output
    assert "2001:db8::1" in output
    assert "TTL: 300s (5m)" in output
    assert "TTL SUMMARY" in output
    assert "not a security score" in output
    assert "remaining TTL" in output


@patch("cli.interface.DNSResolver")
def test_cli_missing_aaaa_is_not_an_error(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 3600)]),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "No AAAA record found." in output


@patch("cli.interface.DNSResolver")
def test_cli_notes_private_scope(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "intranet.example", "10.0.0.5", 60)]),
    )

    assert run(["intranet.example"]) == 0
    assert "Scope: private" in capsys.readouterr().out


@patch("cli.interface.DNSResolver")
def test_cli_prints_cname_mx_ns(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            cname=[DNSRecord("CNAME", "www.example.com", "example.com", 600)],
            mx=[
                DNSRecord("MX", "example.com", "mail-b.example.com", 3600, priority=20),
                DNSRecord("MX", "example.com", "mail-a.example.com", 3600, priority=10),
            ],
            ns=[
                DNSRecord("NS", "example.com", "ns2.example.com", 86400),
                DNSRecord("NS", "example.com", "ns1.example.com", 86400),
            ],
        ),
    )

    assert run(["www.example.com"]) == 0
    output = capsys.readouterr().out
    assert "www.example.com → example.com" in output
    assert "mail-a.example.com" in output
    assert output.find("mail-a.example.com") < output.find("mail-b.example.com")
    assert "Priority: 10" in output
    assert "Priority: 20" in output
    assert output.find("ns1.example.com") < output.find("ns2.example.com")


@patch("cli.interface.DNSResolver")
def test_cli_prints_txt_soa_caa(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            txt=[DNSRecord("TXT", "example.com", "v=spf1 -all", 300)],
            soa=[
                DNSRecord(
                    "SOA",
                    "example.com",
                    "ns1.example.com serial=2026090201",
                    60,
                    details=(
                        ("Primary NS", "ns1.example.com"),
                        ("Mailbox", "hostmaster.example.com"),
                        ("Serial", "2026090201"),
                    ),
                )
            ],
            caa=[
                DNSRecord(
                    "CAA",
                    "example.com",
                    '0 issue "letsencrypt.org"',
                    3600,
                    details=(("Tag", "issue — allows this CA to issue certificates"),),
                )
            ],
        ),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert '"v=spf1 -all"' in output
    assert "Primary NS: ns1.example.com" in output
    assert "Serial: 2026090201" in output
    assert '0 issue "letsencrypt.org"' in output
    assert "No CAA record found." not in output
    assert "SPF" in output
    assert "Status: FOUND" in output
    assert "v=spf1 -all" in output
    assert "HTTPS RECORDS" in output
    assert "No HTTPS record found." in output
    assert "SVCB RECORDS" in output


@patch("cli.interface.DNSResolver")
def test_cli_record_https_skips_security(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            a=[DNSRecord("A", "example.com", "93.184.216.34", 60)],
            https=[
                DNSRecord(
                    "HTTPS",
                    "example.com",
                    "1 . alpn=h2,h3 ech=(present)",
                    60,
                    priority=1,
                    details=(
                        ("Mode", "ServiceMode — this name advertises protocol parameters (RFC 9460)"),
                        ("ALPN", "h2,h3 — application protocols (e.g. HTTP/2, HTTP/3)"),
                        ("ECH", "present — Encrypted Client Hello config in DNS, not a private key"),
                    ),
                )
            ],
        ),
    )

    assert run(["example.com", "--record", "HTTPS"]) == 0
    output = capsys.readouterr().out
    assert "HTTPS RECORDS" in output
    assert "alpn=h2,h3" in output
    assert "ServiceMode" in output
    assert "ech=(present)" in output
    assert "SECURITY ANALYSIS" not in output
    mock_resolver_cls.return_value.inspect_dnssec.assert_not_called()
    mock_resolver_cls.return_value.inspect_cds.assert_not_called()
    mock_resolver_cls.return_value.inspect_nsec.assert_not_called()
    mock_resolver_cls.return_value.inspect_csync.assert_not_called()
    mock_resolver_cls.return_value.inspect_zonemd.assert_not_called()
    mock_resolver_cls.return_value.inspect_rrsig.assert_not_called()
    mock_resolver_cls.return_value.lookup_core.assert_called_once_with(
        "example.com", types=("A", "HTTPS")
    )


@patch("cli.interface.DNSResolver")
def test_cli_shows_section_timeout_not_empty(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            a=[DNSRecord("A", "example.com", "93.184.216.34", 60)],
            errors=(("CAA", "DNS query timed out."),),
        ),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "93.184.216.34" in output
    assert "Error: DNS query timed out." in output
    assert "No CAA record found." not in output


@patch("cli.interface.DNSResolver")
def test_cli_reverse_prints_ptr(mock_resolver_cls, capsys) -> None:
    mock_resolver_cls.return_value.resolve_reverse.return_value = [
        DNSRecord("PTR", "8.8.8.8.in-addr.arpa", "dns.google", 86400),
    ]

    assert run(["--reverse", "8.8.8.8"]) == 0
    output = capsys.readouterr().out
    assert "REVERSE DNS" in output
    assert "8.8.8.8" in output
    assert "→ dns.google" in output
    assert "8.8.8.8.in-addr.arpa" in output


@patch("cli.interface.DNSResolver")
def test_cli_reverse_missing_ptr(mock_resolver_cls, capsys) -> None:
    mock_resolver_cls.return_value.resolve_reverse.return_value = []

    assert run(["--reverse", "203.0.113.1"]) == 0
    assert "No PTR record found." in capsys.readouterr().out


def test_cli_positional_ip_hints_reverse(capsys) -> None:
    assert run(["8.8.8.8"]) == 1
    assert "--reverse" in capsys.readouterr().err


def test_cli_url_ip_hints_reverse(capsys) -> None:
    assert run(["http://127.0.0.1/"]) == 1
    assert "--reverse" in capsys.readouterr().err


@patch("cli.interface.DNSResolver")
def test_cli_prints_dnssec_detected(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        dnssec=_dnssec(dnskey_found=True, ds_found=True, ad_flag=True),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "DNSSEC" in output
    assert "Status: DETECTED" in output
    assert "DNSKEY: FOUND" in output
    assert "DS:     FOUND" in output
    assert "AD flag: SET" in output
    assert "does not mean the domain is compromised" in output
    assert "strip DNSKEY" in output


@patch("cli.interface.DNSResolver")
def test_cli_prints_dnssec_key_algorithms(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        dnssec=_dnssec(
            dnskey_found=True,
            ds_found=True,
            ad_flag=True,
            keys=(
                DnssecKey(
                    flags=257,
                    protocol=3,
                    algorithm=15,
                    algorithm_meaning="Ed25519",
                    role="KSK",
                    zone_key=True,
                    secure_entry_point=True,
                    key_tag=12345,
                ),
            ),
            delegations=(
                DnssecDelegation(
                    key_tag=12345,
                    algorithm=13,
                    algorithm_meaning="ECDSAP256SHA256",
                    digest_type=2,
                    digest_meaning="SHA-256",
                ),
            ),
        ),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "257 3 15" in output
    assert "Ed25519" in output
    assert "KSK" in output
    assert "SHA-256" in output
    assert "ECDSAP256SHA256" in output


@patch("cli.interface.DNSResolver")
def test_cli_prints_cds_records(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        cds=evaluate_cds(
            "example.com",
            cds_found=True,
            cdnskey_found=True,
            cds=(
                CdsRecord(
                    key_tag=2371,
                    algorithm=13,
                    algorithm_meaning="ECDSAP256SHA256",
                    digest_type=2,
                    digest_meaning="SHA-256",
                ),
            ),
            cdnskey=(
                CdnskeyRecord(
                    flags=257,
                    protocol=3,
                    algorithm=13,
                    algorithm_meaning="ECDSAP256SHA256",
                    role="KSK",
                    zone_key=True,
                    secure_entry_point=True,
                    key_tag=2371,
                ),
            ),
        ),
    )

    assert run(["example.com", "--security"]) == 0
    output = capsys.readouterr().out
    assert "CDS / CDNSKEY" in output
    assert "Status: FOUND" in output
    assert "2371 13 2" in output
    assert "SHA-256" in output
    assert "257 3 13" in output
    assert "KSK" in output
    assert "parent registry" in output
    mock_resolver_cls.return_value.inspect_cds.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_nsec.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_csync.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_zonemd.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_rrsig.assert_called_once_with("example.com")


@patch("cli.interface.DNSResolver")
def test_cli_prints_nsec_records(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        nsec=evaluate_nsec(
            "example.com",
            nsec_found=True,
            nsec3param_found=True,
            nsec=(
                NsecRecord(
                    next_name="www.example.com",
                    types=("A", "NS", "SOA", "DNSKEY", "NSEC", "RRSIG"),
                ),
            ),
            nsec3param=(
                Nsec3ParamRecord(
                    algorithm=1,
                    algorithm_meaning="SHA-1 (NSEC3 hash)",
                    flags=1,
                    opt_out=True,
                    iterations=0,
                    salt_length=8,
                    iterations_note="0 iterations (RFC 9276)",
                ),
            ),
        ),
    )

    assert run(["example.com", "--security"]) == 0
    output = capsys.readouterr().out
    assert "NSEC / NSEC3PARAM" in output
    assert "Status: FOUND" in output
    assert "www.example.com" in output
    assert "salt length 8" in output
    assert "does not walk" in output
    mock_resolver_cls.return_value.inspect_nsec.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_csync.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_zonemd.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_rrsig.assert_called_once_with("example.com")


@patch("cli.interface.DNSResolver")
def test_cli_prints_csync_records(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        csync=evaluate_csync(
            "example.com",
            found=True,
            csync=(
                CsyncRecord(
                    serial=2026091501,
                    flags=3,
                    immediate=True,
                    soa_minimum=True,
                    types=("NS", "A", "AAAA"),
                ),
            ),
        ),
    )

    assert run(["example.com", "--security"]) == 0
    output = capsys.readouterr().out
    assert "CSYNC" in output
    assert "Status: FOUND" in output
    assert "2026091501" in output
    assert "immediate" in output
    assert "parent registry" in output
    mock_resolver_cls.return_value.inspect_csync.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_zonemd.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_rrsig.assert_called_once_with("example.com")


@patch("cli.interface.DNSResolver")
def test_cli_prints_zonemd_records(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        zonemd=evaluate_zonemd(
            "example.com",
            found=True,
            zonemd=(
                ZonemdRecord(
                    serial=2026091601,
                    scheme=1,
                    scheme_meaning="SIMPLE",
                    hash_algorithm=1,
                    hash_meaning="SHA-384",
                    digest_length=48,
                ),
            ),
        ),
    )

    assert run(["example.com", "--security"]) == 0
    output = capsys.readouterr().out
    assert "ZONEMD" in output
    assert "Status: FOUND" in output
    assert "2026091601" in output
    assert "SHA-384" in output
    assert "digest length 48" in output
    assert "AXFR" in output
    mock_resolver_cls.return_value.inspect_zonemd.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_rrsig.assert_called_once_with("example.com")


@patch("cli.interface.DNSResolver")
def test_cli_prints_rrsig_records(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        rrsig=evaluate_rrsig(
            "example.com",
            found=True,
            rrsig=(
                RrsigRecord(
                    type_covered=1,
                    type_covered_name="A",
                    algorithm=13,
                    algorithm_meaning="ECDSAP256SHA256",
                    labels=2,
                    original_ttl=300,
                    inception=1758240000,
                    expiration=1760918400,
                    inception_utc="2025-09-19T00:00:00Z",
                    expiration_utc="2025-10-20T00:00:00Z",
                    key_tag=2371,
                    signer="example.com",
                    signature_length=64,
                ),
            ),
        ),
    )

    assert run(["example.com", "--security"]) == 0
    output = capsys.readouterr().out
    assert "RRSIG" in output
    assert "Status: FOUND" in output
    assert "ECDSAP256SHA256" in output
    assert "key 2371" in output
    assert "sig length 64" in output
    assert "not validate" in output
    mock_resolver_cls.return_value.inspect_rrsig.assert_called_once_with("example.com")


@patch("cli.interface.DNSResolver")
def test_cli_prints_dmarc_reject(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        dmarc=_dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@example.com"),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "DMARC" in output
    assert "Status: FOUND" in output
    assert "p=reject" in output
    assert "_dmarc.example.com" in output
    assert "does not mean the domain is compromised" in output


@patch("cli.interface.DNSResolver")
def test_cli_prints_mta_sts(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        mtasts=_mtasts("v=STSv1; id=20160831085700Z"),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "MTA-STS" in output
    assert "Status: FOUND" in output
    assert "_mta-sts.example.com" in output
    assert "id=20160831085700Z" in output
    assert "HTTPS file not fetched" in output
    mock_resolver_cls.return_value.inspect_mta_sts.assert_called_once_with("example.com")


@patch("cli.interface.DNSResolver")
def test_cli_prints_tls_rpt(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        tlsrpt=_tlsrpt("v=TLSRPTv1; rua=mailto:tlsrpt@example.com"),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "TLS-RPT" in output
    assert "Status: FOUND" in output
    assert "_smtp._tls.example.com" in output
    assert "rua=mailto:tlsrpt@example.com" in output
    mock_resolver_cls.return_value.inspect_tls_rpt.assert_called_once_with("example.com")


@patch("cli.interface.DNSResolver")
def test_cli_prints_bimi(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        bimi=_bimi("v=BIMI1; l=https://example.com/logo.svg"),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "BIMI" in output
    assert "Status: FOUND" in output
    assert "default._bimi.example.com" in output
    assert "l=https://example.com/logo.svg" in output
    assert "URL not fetched" in output
    mock_resolver_cls.return_value.inspect_bimi.assert_called_once_with("example.com")


@patch("cli.interface.DNSResolver")
def test_cli_prints_tlsa(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        tlsa=_tlsa(f"3 1 1 {'ab' * 32}"),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "DANE / TLSA" in output
    assert "Status: FOUND" in output
    assert "_443._tcp.example.com" in output
    assert "DANE-EE" in output
    mock_resolver_cls.return_value.inspect_tlsa.assert_called_once_with("example.com")


@patch("cli.interface.DNSResolver")
def test_cli_prints_sshfp(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        sshfp=_sshfp(f"4 2 {'ab' * 32}"),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "SSHFP" in output
    assert "Status: FOUND" in output
    assert "Ed25519" in output
    mock_resolver_cls.return_value.inspect_sshfp.assert_called_once_with("example.com")


@patch("cli.interface.DNSResolver")
def test_cli_prints_fcrdns(mock_resolver_cls, capsys) -> None:
    check = FcrdnsCheck(
        ip="93.184.216.34",
        ptr_query="34.216.184.93.in-addr.arpa",
        ptr_names=("example.com",),
        forward_ips=("93.184.216.34",),
        status="CONFIRMED",
    )
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        fcrdns=_fcrdns(check),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "FCrDNS" in output
    assert "Status: CONFIRMED" in output
    assert "34.216.184.93.in-addr.arpa" in output
    mock_resolver_cls.return_value.inspect_fcrdns.assert_called_once()


@patch("cli.interface.DNSResolver")
def test_cli_prints_mx_hosts(mock_resolver_cls, capsys) -> None:
    from analyzer.mx import MxHostCheck

    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        mx_hosts=_mx_hosts(
            MxHostCheck(
                host="mail.example.com",
                preference=10,
                ipv4=("192.0.2.10",),
                ipv6=(),
                status="RESOLVES",
            )
        ),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "MX HOSTS" in output
    assert "Status: RESOLVES" in output
    assert "mail.example.com" in output
    mock_resolver_cls.return_value.inspect_mx_hosts.assert_called_once_with("example.com")


@patch("cli.interface.DNSResolver")
def test_cli_prints_ns_hosts(mock_resolver_cls, capsys) -> None:
    from analyzer.ns import NsHostCheck

    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        ns_hosts=_ns_hosts(
            NsHostCheck(
                host="ns1.example.com",
                in_bailiwick=True,
                ipv4=("192.0.2.53",),
                ipv6=(),
                status="RESOLVES",
            )
        ),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "NS HOSTS" in output
    assert "Status: RESOLVES" in output
    assert "in-bailiwick" in output
    assert "ns1.example.com" in output
    mock_resolver_cls.return_value.inspect_ns_hosts.assert_called_once_with("example.com")


@patch("cli.interface.DNSResolver")
def test_cli_prints_cname_targets(mock_resolver_cls, capsys) -> None:
    from analyzer.cname import CnameTargetCheck

    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        cname_targets=_cname_targets(
            CnameTargetCheck(
                target="cdn.example.net",
                chain=("cdn.example.net",),
                ipv4=("192.0.2.10",),
                ipv6=(),
                status="RESOLVES",
            )
        ),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "CNAME TARGETS" in output
    assert "Status: RESOLVES" in output
    assert "cdn.example.net" in output
    mock_resolver_cls.return_value.inspect_cname_targets.assert_called_once()


@patch("cli.interface.DNSResolver")
def test_cli_prints_soa_ns(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        soa_ns=evaluate_soa_ns(
            "example.com",
            "ns1.example.com",
            ("ns1.example.com", "ns2.example.com"),
            serial="2026091301",
        ),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "SOA / NS" in output
    assert "Status: ALIGNED" in output
    assert "ns1.example.com" in output
    mock_resolver_cls.return_value.inspect_soa_ns.assert_called_once_with("example.com")


@patch("cli.interface.DNSResolver")
def test_cli_prints_caa_summary(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
        caa=evaluate_caa(
            "example.com",
            [
                DNSRecord("CAA", "example.com", '0 issue "letsencrypt.org"', 3600),
                DNSRecord("CAA", "example.com", '0 issuewild "letsencrypt.org"', 3600),
                DNSRecord(
                    "CAA", "example.com", '0 iodef "mailto:caa@example.com"', 3600
                ),
            ],
        ),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "issue: letsencrypt.org" in output
    assert "issuewild: letsencrypt.org" in output
    assert "iodef: mailto:caa@example.com" in output
    assert "Status: FOUND" in output
    mock_resolver_cls.return_value.inspect_caa.assert_called_once_with("example.com")


@patch("cli.interface.DNSResolver")
def test_cli_prints_spf_include_hop(mock_resolver_cls, capsys) -> None:
    from dataclasses import replace

    from analyzer.spf import SpfHop, inspect_spf

    _bind(
        mock_resolver_cls,
        _lookup(
            a=[DNSRecord("A", "example.com", "93.184.216.34", 60)],
            txt=[DNSRecord("TXT", "example.com", "v=spf1 include:_spf.google.com ~all", 300)],
        ),
    )
    base = inspect_spf(
        [DNSRecord("TXT", "example.com", "v=spf1 include:_spf.google.com ~all", 300)]
    )
    mock_resolver_cls.return_value.expand_spf.side_effect = None
    mock_resolver_cls.return_value.expand_spf.return_value = replace(
        base,
        hops=(
            SpfHop(
                kind="include",
                domain="_spf.google.com",
                status="FOUND",
                policy="v=spf1 include:_netblocks.google.com ~all",
                all_term="~all",
                all_meaning="softfail — often accepted but marked as suspicious",
                nested_includes=("_netblocks.google.com",),
            ),
        ),
    )

    assert run(["example.com", "--security"]) == 0
    output = capsys.readouterr().out
    assert "include _spf.google.com:" in output
    assert "nested include: _netblocks.google.com (not followed)" in output
    mock_resolver_cls.return_value.expand_spf.assert_called()


@patch("cli.interface.DNSResolver")
def test_cli_prints_security_observations(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )

    assert run(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "SECURITY ANALYSIS" in output
    assert "[LOW] SPF not published" in output
    assert "[LOW] DMARC not published" in output
    assert "[HIGH]" not in output
    assert "not vulnerability scanner results" in output
    assert "RISK SCORE" in output
    assert "Band:" in output
    assert "not CVSS" in output
    assert "Contributions:" in output
    assert "+10  DMARC not published" in output
    assert "+5  DNSSEC not detected by this resolver" in output


@patch("cli.interface.DNSResolver")
def test_cli_security_flags_private_address(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "intranet.example", "10.0.0.5", 60)]),
    )

    assert run(["intranet.example"]) == 0
    output = capsys.readouterr().out
    assert "[MEDIUM] A points to a private address" in output
    assert "Scope: private" in output


@patch("cli.interface.DNSResolver")
def test_cli_record_filter_hides_other_sections(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            a=[DNSRecord("A", "example.com", "93.184.216.34", 3600)],
            mx=[DNSRecord("MX", "example.com", "mail.example.com", 3600, priority=10)],
        ),
    )

    assert run(["example.com", "--record", "a"]) == 0
    output = capsys.readouterr().out
    assert "A RECORDS" in output
    assert "93.184.216.34" in output
    assert "MX RECORDS" not in output
    assert "mail.example.com" not in output
    assert "SECURITY ANALYSIS" not in output
    assert "RISK SCORE" not in output
    mock_resolver_cls.return_value.inspect_dnssec.assert_not_called()
    mock_resolver_cls.return_value.inspect_cds.assert_not_called()
    mock_resolver_cls.return_value.inspect_nsec.assert_not_called()
    mock_resolver_cls.return_value.inspect_csync.assert_not_called()
    mock_resolver_cls.return_value.inspect_zonemd.assert_not_called()
    mock_resolver_cls.return_value.inspect_rrsig.assert_not_called()
    mock_resolver_cls.return_value.inspect_dmarc.assert_not_called()
    mock_resolver_cls.return_value.inspect_mta_sts.assert_not_called()
    mock_resolver_cls.return_value.inspect_tls_rpt.assert_not_called()
    mock_resolver_cls.return_value.inspect_bimi.assert_not_called()
    mock_resolver_cls.return_value.inspect_tlsa.assert_not_called()
    mock_resolver_cls.return_value.inspect_sshfp.assert_not_called()
    mock_resolver_cls.return_value.inspect_fcrdns.assert_not_called()
    mock_resolver_cls.return_value.inspect_mx_hosts.assert_not_called()
    mock_resolver_cls.return_value.inspect_ns_hosts.assert_not_called()
    mock_resolver_cls.return_value.inspect_cname_targets.assert_not_called()
    mock_resolver_cls.return_value.inspect_soa_ns.assert_not_called()
    mock_resolver_cls.return_value.inspect_caa.assert_not_called()
    mock_resolver_cls.return_value.inspect_cds.assert_not_called()
    mock_resolver_cls.return_value.inspect_nsec.assert_not_called()
    mock_resolver_cls.return_value.inspect_csync.assert_not_called()
    mock_resolver_cls.return_value.inspect_zonemd.assert_not_called()
    mock_resolver_cls.return_value.inspect_rrsig.assert_not_called()
    mock_resolver_cls.return_value.inspect_dkim.assert_not_called()
    mock_resolver_cls.return_value.inspect_srv.assert_not_called()
    mock_resolver_cls.return_value.inspect_naptr.assert_not_called()
    mock_resolver_cls.return_value.inspect_uri.assert_not_called()
    mock_resolver_cls.return_value.inspect_dname.assert_not_called()
    mock_resolver_cls.return_value.inspect_ipseckey.assert_not_called()
    mock_resolver_cls.return_value.inspect_smimea.assert_not_called()
    mock_resolver_cls.return_value.lookup_core.assert_called_once_with(
        "example.com", types=("A",)
    )


@patch("cli.interface.DNSResolver")
def test_cli_record_can_be_repeated(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            a=[DNSRecord("A", "example.com", "93.184.216.34", 60)],
            mx=[DNSRecord("MX", "example.com", "mail.example.com", 60, priority=10)],
            ns=[DNSRecord("NS", "example.com", "ns1.example.com", 86400)],
        ),
    )

    assert run(["example.com", "--record", "MX", "--record", "NS"]) == 0
    output = capsys.readouterr().out
    assert "MX RECORDS" in output
    assert "NS RECORDS" in output
    assert "A RECORDS" not in output
    assert "SECURITY ANALYSIS" not in output
    mock_resolver_cls.return_value.lookup_core.assert_called_once_with(
        "example.com", types=("A", "MX", "NS")
    )


@patch("cli.interface.DNSResolver")
def test_cli_security_flag_skips_record_dump(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )

    assert run(["example.com", "--security"]) == 0
    output = capsys.readouterr().out
    assert "A RECORDS" not in output
    assert "TTL SUMMARY" not in output
    assert "DNSSEC" in output
    assert "SPF" in output
    assert "DMARC" in output
    assert "SECURITY ANALYSIS" in output
    assert "RISK SCORE" in output
    mock_resolver_cls.return_value.inspect_dnssec.assert_called_once()
    mock_resolver_cls.return_value.inspect_cds.assert_called_once()
    mock_resolver_cls.return_value.inspect_nsec.assert_called_once()
    mock_resolver_cls.return_value.inspect_csync.assert_called_once()
    mock_resolver_cls.return_value.inspect_zonemd.assert_called_once()
    mock_resolver_cls.return_value.inspect_rrsig.assert_called_once()
    mock_resolver_cls.return_value.inspect_naptr.assert_not_called()
    mock_resolver_cls.return_value.inspect_uri.assert_not_called()
    mock_resolver_cls.return_value.inspect_dname.assert_not_called()
    mock_resolver_cls.return_value.inspect_ipseckey.assert_not_called()
    mock_resolver_cls.return_value.inspect_smimea.assert_not_called()
    mock_resolver_cls.return_value.lookup_core.assert_called_once_with(
        "example.com", types=("A", "AAAA", "CNAME", "TXT", "CAA")
    )


@patch("cli.interface.DNSResolver")
def test_cli_record_plus_security(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            a=[DNSRecord("A", "example.com", "93.184.216.34", 60)],
            mx=[DNSRecord("MX", "example.com", "mail.example.com", 60, priority=10)],
        ),
    )

    assert run(["example.com", "--record", "A", "--security"]) == 0
    output = capsys.readouterr().out
    assert "A RECORDS" in output
    assert "MX RECORDS" not in output
    assert "SECURITY ANALYSIS" in output
    mock_resolver_cls.return_value.lookup_core.assert_called_once_with(
        "example.com", types=("A", "AAAA", "CNAME", "TXT", "CAA")
    )


@patch("cli.interface.DNSResolver")
def test_cli_all_flag_is_full_report(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )

    assert run(["example.com", "--all"]) == 0
    output = capsys.readouterr().out
    assert "A RECORDS" in output
    assert "SECURITY ANALYSIS" in output
    assert "RISK SCORE" in output
    mock_resolver_cls.return_value.inspect_uri.assert_not_called()
    mock_resolver_cls.return_value.inspect_dname.assert_not_called()
    mock_resolver_cls.return_value.inspect_ipseckey.assert_not_called()
    mock_resolver_cls.return_value.inspect_smimea.assert_not_called()


def test_cli_rejects_unknown_record_type(capsys) -> None:
    assert run(["example.com", "--record", "FOO"]) == 1
    assert "Unknown record type" in capsys.readouterr().err


def test_cli_record_ptr_hints_reverse(capsys) -> None:
    assert run(["example.com", "--record", "PTR"]) == 1
    assert "--reverse" in capsys.readouterr().err


def test_cli_record_srv_hints_srv_flag(capsys) -> None:
    assert run(["example.com", "--record", "SRV"]) == 1
    err = capsys.readouterr().err
    assert "--srv" in err
    assert "apex" in err.lower() or "not at the apex" in err.lower()


def test_cli_record_tlsa_hints_dane(capsys) -> None:
    assert run(["example.com", "--record", "TLSA"]) == 1
    err = capsys.readouterr().err
    assert "_443._tcp" in err
    assert "apex" in err.lower()


def test_cli_record_sshfp_hints_security_view(capsys) -> None:
    assert run(["example.com", "--record", "SSHFP"]) == 1
    err = capsys.readouterr().err
    assert "SSHFP" in err
    assert "--security" in err or "security" in err.lower()


def test_cli_record_cds_hints_security_view(capsys) -> None:
    assert run(["example.com", "--record", "CDS"]) == 1
    err = capsys.readouterr().err
    assert "CDS" in err
    assert "--security" in err or "security" in err.lower()


def test_cli_record_cdnskey_hints_security_view(capsys) -> None:
    assert run(["example.com", "--record", "CDNSKEY"]) == 1
    err = capsys.readouterr().err
    assert "CDNSKEY" in err
    assert "--security" in err or "security" in err.lower()


def test_cli_record_nsec_hints_security_view(capsys) -> None:
    assert run(["example.com", "--record", "NSEC"]) == 1
    err = capsys.readouterr().err
    assert "NSEC" in err
    assert "walk" in err.lower() or "--security" in err or "security" in err.lower()


def test_cli_record_nsec3param_hints_security_view(capsys) -> None:
    assert run(["example.com", "--record", "NSEC3PARAM"]) == 1
    err = capsys.readouterr().err
    assert "NSEC" in err
    assert "walk" in err.lower() or "--security" in err or "security" in err.lower()


def test_cli_record_csync_hints_security_view(capsys) -> None:
    assert run(["example.com", "--record", "CSYNC"]) == 1
    err = capsys.readouterr().err
    assert "CSYNC" in err
    assert "--security" in err or "security" in err.lower()


def test_cli_record_zonemd_hints_security_view(capsys) -> None:
    assert run(["example.com", "--record", "ZONEMD"]) == 1
    err = capsys.readouterr().err
    assert "ZONEMD" in err
    assert "AXFR" in err or "--security" in err or "security" in err.lower()


def test_cli_record_rrsig_hints_security_view(capsys) -> None:
    assert run(["example.com", "--record", "RRSIG"]) == 1
    err = capsys.readouterr().err
    assert "RRSIG" in err
    assert "validate" in err.lower() or "--security" in err or "security" in err.lower()


def test_cli_rejects_all_with_record(capsys) -> None:
    assert run(["example.com", "--all", "--record", "A"]) == 1
    assert "Do not combine --all" in capsys.readouterr().err


def test_cli_rejects_reverse_with_security(capsys) -> None:
    assert run(["--reverse", "8.8.8.8", "--security"]) == 1
    assert "--reverse" in capsys.readouterr().err


def test_cli_rejects_reverse_with_dkim(capsys) -> None:
    assert run(["--reverse", "8.8.8.8", "--dkim", "google"]) == 1
    assert "--reverse" in capsys.readouterr().err


def test_cli_rejects_reverse_with_srv(capsys) -> None:
    assert run(["--reverse", "8.8.8.8", "--srv", "sip"]) == 1
    assert "--reverse" in capsys.readouterr().err


def test_cli_record_naptr_hints_naptr_flag(capsys) -> None:
    assert run(["example.com", "--record", "NAPTR"]) == 1
    err = capsys.readouterr().err
    assert "--naptr" in err
    assert "opt-in" in err.lower() or "ENUM" in err


def test_cli_rejects_reverse_with_naptr(capsys) -> None:
    assert run(["--reverse", "8.8.8.8", "--naptr"]) == 1
    assert "--reverse" in capsys.readouterr().err


def test_cli_rejects_invalid_dkim_selector(capsys) -> None:
    assert run(["example.com", "--dkim", "*.google"]) == 1
    assert "Invalid DKIM selector" in capsys.readouterr().err


@patch("cli.interface.DNSResolver")
def test_cli_dkim_prints_section(mock_resolver_cls, capsys) -> None:
    from analyzer.dkim import evaluate_dkim

    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    mock_resolver_cls.return_value.inspect_dkim.return_value = evaluate_dkim(
        "google._domainkey.example.com",
        "google",
        [DNSRecord("TXT", "google._domainkey.example.com", "v=DKIM1; k=rsa; p=MIIBIjAN", 300)],
    )

    assert run(["example.com", "--record", "A", "--dkim", "google"]) == 0
    output = capsys.readouterr().out
    assert "DKIM" in output
    assert "google._domainkey.example.com" in output
    assert "FOUND" in output
    assert "present" in output
    assert "MIIBIjAN" not in output
    assert "SECURITY ANALYSIS" not in output
    mock_resolver_cls.return_value.inspect_dkim.assert_called_once_with(
        "example.com", "google"
    )
    mock_resolver_cls.return_value.inspect_dnssec.assert_not_called()
    mock_resolver_cls.return_value.inspect_cds.assert_not_called()
    mock_resolver_cls.return_value.inspect_nsec.assert_not_called()
    mock_resolver_cls.return_value.inspect_csync.assert_not_called()
    mock_resolver_cls.return_value.inspect_zonemd.assert_not_called()
    mock_resolver_cls.return_value.inspect_rrsig.assert_not_called()


@patch("cli.interface.DNSResolver")
def test_cli_dkim_json_includes_observation(mock_resolver_cls, capsys) -> None:
    from analyzer.dkim import evaluate_dkim

    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    mock_resolver_cls.return_value.inspect_dkim.return_value = evaluate_dkim(
        "google._domainkey.example.com",
        "google",
        [DNSRecord("TXT", "google._domainkey.example.com", "v=DKIM1; p=MIIB", 300)],
    )

    assert run(["example.com", "--dkim", "google", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["dkim"][0]["selector"] == "google"
    assert data["dkim"][0]["status"] == "FOUND"


@patch("cli.interface.DNSResolver")
def test_cli_srv_prints_section(mock_resolver_cls, capsys) -> None:
    from analyzer.srv import SrvSpec, evaluate_srv

    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    mock_resolver_cls.return_value.inspect_srv.return_value = evaluate_srv(
        "_sip._tcp.example.com",
        SrvSpec("sip", "tcp"),
        [
            DNSRecord(
                "SRV",
                "_sip._tcp.example.com",
                "10 5 5060 sip.example.com",
                300,
                priority=10,
                details=(
                    ("Priority", "10 — lower number is tried first"),
                    ("Weight", "5 — among the same priority"),
                    ("Port", "5060"),
                    ("Target", "sip.example.com"),
                ),
            )
        ],
    )

    assert run(["example.com", "--record", "A", "--srv", "sip"]) == 0
    output = capsys.readouterr().out
    assert "SRV" in output
    assert "_sip._tcp.example.com" in output
    assert "FOUND" in output
    assert "5060" in output
    assert "SECURITY ANALYSIS" not in output
    mock_resolver_cls.return_value.inspect_srv.assert_called_once()
    mock_resolver_cls.return_value.inspect_dnssec.assert_not_called()
    mock_resolver_cls.return_value.inspect_cds.assert_not_called()
    mock_resolver_cls.return_value.inspect_nsec.assert_not_called()
    mock_resolver_cls.return_value.inspect_csync.assert_not_called()
    mock_resolver_cls.return_value.inspect_zonemd.assert_not_called()
    mock_resolver_cls.return_value.inspect_rrsig.assert_not_called()
    called_spec = mock_resolver_cls.return_value.inspect_srv.call_args[0][1]
    assert called_spec.service == "sip"
    assert called_spec.protocol == "tcp"


@patch("cli.interface.DNSResolver")
def test_cli_srv_json_includes_observation(mock_resolver_cls, capsys) -> None:
    from analyzer.srv import SrvSpec, evaluate_srv

    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    mock_resolver_cls.return_value.inspect_srv.return_value = evaluate_srv(
        "_sip._udp.example.com",
        SrvSpec("sip", "udp"),
        [
            DNSRecord(
                "SRV",
                "_sip._udp.example.com",
                "0 0 5060 sip.example.com",
                60,
                priority=0,
            )
        ],
    )

    assert run(["example.com", "--srv", "sip/udp", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["srv"][0]["service"] == "sip"
    assert data["srv"][0]["protocol"] == "udp"
    assert data["srv"][0]["status"] == "FOUND"


def test_cli_rejects_invalid_srv_service(capsys) -> None:
    assert run(["example.com", "--srv", "*.sip"]) == 1
    assert "Invalid SRV service" in capsys.readouterr().err


@patch("cli.interface.DNSResolver")
def test_cli_naptr_prints_section(mock_resolver_cls, capsys) -> None:
    from analyzer.naptr import evaluate_naptr

    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    mock_resolver_cls.return_value.inspect_naptr.return_value = evaluate_naptr(
        "example.com",
        [
            DNSRecord(
                "NAPTR",
                "example.com",
                '100 50 "u" "E2U+sip" "!^.*$!sip:info@example.com!" .',
                300,
            )
        ],
    )

    assert run(["example.com", "--record", "A", "--naptr"]) == 0
    output = capsys.readouterr().out
    assert "NAPTR" in output
    assert "FOUND" in output
    assert "E2U+sip" in output
    assert "SECURITY ANALYSIS" not in output
    mock_resolver_cls.return_value.inspect_naptr.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_dnssec.assert_not_called()
    mock_resolver_cls.return_value.inspect_cds.assert_not_called()
    mock_resolver_cls.return_value.inspect_nsec.assert_not_called()
    mock_resolver_cls.return_value.inspect_csync.assert_not_called()
    mock_resolver_cls.return_value.inspect_zonemd.assert_not_called()
    mock_resolver_cls.return_value.inspect_rrsig.assert_not_called()


@patch("cli.interface.DNSResolver")
def test_cli_naptr_json_includes_observation(mock_resolver_cls, capsys) -> None:
    from analyzer.naptr import evaluate_naptr

    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    mock_resolver_cls.return_value.inspect_naptr.return_value = evaluate_naptr(
        "example.com",
        [
            DNSRecord(
                "NAPTR",
                "example.com",
                '10 10 "s" "SIP+D2T" "" _sip._tcp.example.com.',
                60,
            )
        ],
    )

    assert run(["example.com", "--naptr", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["naptr"]["status"] == "FOUND"
    assert data["naptr"]["rewrites"][0]["flags"] == "s"
    assert data["naptr"]["rewrites"][0]["replacement"] == "_sip._tcp.example.com"


def test_cli_record_uri_hints_uri_flag(capsys) -> None:
    assert run(["example.com", "--record", "URI"]) == 1
    err = capsys.readouterr().err
    assert "--uri" in err
    assert "opt-in" in err.lower() or "_http._tcp" in err


def test_cli_rejects_reverse_with_uri(capsys) -> None:
    assert run(["--reverse", "8.8.8.8", "--uri"]) == 1
    assert "--reverse" in capsys.readouterr().err


@patch("cli.interface.DNSResolver")
def test_cli_uri_prints_section(mock_resolver_cls, capsys) -> None:
    from analyzer.uri import evaluate_uri

    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    mock_resolver_cls.return_value.inspect_uri.return_value = evaluate_uri(
        "example.com",
        [
            DNSRecord(
                "URI",
                "example.com",
                '10 1 "https://www.example.com/path"',
                300,
            )
        ],
    )

    assert run(["example.com", "--record", "A", "--uri"]) == 0
    output = capsys.readouterr().out
    assert "URI" in output
    assert "FOUND" in output
    assert "https://www.example.com/path" in output
    assert "SECURITY ANALYSIS" not in output
    mock_resolver_cls.return_value.inspect_uri.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_dname.assert_not_called()
    mock_resolver_cls.return_value.inspect_ipseckey.assert_not_called()
    mock_resolver_cls.return_value.inspect_smimea.assert_not_called()
    mock_resolver_cls.return_value.inspect_dnssec.assert_not_called()
    mock_resolver_cls.return_value.inspect_cds.assert_not_called()
    mock_resolver_cls.return_value.inspect_nsec.assert_not_called()
    mock_resolver_cls.return_value.inspect_csync.assert_not_called()
    mock_resolver_cls.return_value.inspect_zonemd.assert_not_called()
    mock_resolver_cls.return_value.inspect_rrsig.assert_not_called()


@patch("cli.interface.DNSResolver")
def test_cli_uri_json_includes_observation(mock_resolver_cls, capsys) -> None:
    from analyzer.uri import evaluate_uri

    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    mock_resolver_cls.return_value.inspect_uri.return_value = evaluate_uri(
        "example.com",
        [
            DNSRecord(
                "URI",
                "example.com",
                '20 5 "ftp://ftp.example.com/pub"',
                60,
            )
        ],
    )

    assert run(["example.com", "--uri", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["uri"]["status"] == "FOUND"
    assert data["uri"]["uris"][0]["scheme"] == "ftp"
    assert data["uri"]["uris"][0]["target"] == "ftp://ftp.example.com/pub"


def test_cli_record_dname_hints_dname_flag(capsys) -> None:
    assert run(["example.com", "--record", "DNAME"]) == 1
    err = capsys.readouterr().err
    assert "--dname" in err
    assert "opt-in" in err.lower() or "subtree" in err.lower() or "synthesize" in err.lower()


def test_cli_rejects_reverse_with_dname(capsys) -> None:
    assert run(["--reverse", "8.8.8.8", "--dname"]) == 1
    assert "--reverse" in capsys.readouterr().err


@patch("cli.interface.DNSResolver")
def test_cli_dname_prints_section(mock_resolver_cls, capsys) -> None:
    from analyzer.dname import evaluate_dname

    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    mock_resolver_cls.return_value.inspect_dname.return_value = evaluate_dname(
        "example.com",
        [DNSRecord("DNAME", "example.com", "other.example.net", 300)],
    )

    assert run(["example.com", "--record", "A", "--dname"]) == 0
    output = capsys.readouterr().out
    assert "DNAME" in output
    assert "FOUND" in output
    assert "other.example.net" in output
    assert "SECURITY ANALYSIS" not in output
    mock_resolver_cls.return_value.inspect_dname.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_dnssec.assert_not_called()
    mock_resolver_cls.return_value.inspect_zonemd.assert_not_called()
    mock_resolver_cls.return_value.inspect_rrsig.assert_not_called()


@patch("cli.interface.DNSResolver")
def test_cli_dname_json_includes_observation(mock_resolver_cls, capsys) -> None:
    from analyzer.dname import evaluate_dname

    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    mock_resolver_cls.return_value.inspect_dname.return_value = evaluate_dname(
        "example.com",
        [DNSRecord("DNAME", "example.com", "other.example.net", 60)],
    )

    assert run(["example.com", "--dname", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["dname"]["status"] == "FOUND"
    assert data["dname"]["dnames"][0]["target"] == "other.example.net"


def test_cli_record_ipseckey_hints_ipseckey_flag(capsys) -> None:
    assert run(["example.com", "--record", "IPSECKEY"]) == 1
    err = capsys.readouterr().err
    assert "--ipseckey" in err
    assert "opt-in" in err.lower() or "ipsec" in err.lower()


def test_cli_rejects_reverse_with_ipseckey(capsys) -> None:
    assert run(["--reverse", "8.8.8.8", "--ipseckey"]) == 1
    assert "--reverse" in capsys.readouterr().err


@patch("cli.interface.DNSResolver")
def test_cli_ipseckey_prints_section(mock_resolver_cls, capsys) -> None:
    from analyzer.ipseckey import evaluate_ipseckey

    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    mock_resolver_cls.return_value.inspect_ipseckey.return_value = evaluate_ipseckey(
        "example.com",
        [DNSRecord("IPSECKEY", "example.com", "10 1 2 192.0.2.1 key-length=64", 300)],
    )

    assert run(["example.com", "--record", "A", "--ipseckey"]) == 0
    output = capsys.readouterr().out
    assert "IPSECKEY" in output
    assert "FOUND" in output
    assert "192.0.2.1" in output
    assert "SECURITY ANALYSIS" not in output
    mock_resolver_cls.return_value.inspect_ipseckey.assert_called_once_with("example.com")
    mock_resolver_cls.return_value.inspect_dnssec.assert_not_called()
    mock_resolver_cls.return_value.inspect_dname.assert_not_called()
    mock_resolver_cls.return_value.inspect_uri.assert_not_called()


@patch("cli.interface.DNSResolver")
def test_cli_ipseckey_json_includes_observation(mock_resolver_cls, capsys) -> None:
    from analyzer.ipseckey import evaluate_ipseckey

    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    mock_resolver_cls.return_value.inspect_ipseckey.return_value = evaluate_ipseckey(
        "example.com",
        [DNSRecord("IPSECKEY", "example.com", "10 1 2 192.0.2.1 key-length=64", 60)],
    )

    assert run(["example.com", "--ipseckey", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ipseckey"]["status"] == "FOUND"
    assert data["ipseckey"]["ipseckeys"][0]["gateway"] == "192.0.2.1"
    assert data["ipseckey"]["ipseckeys"][0]["key_length"] == 64


def test_cli_record_smimea_hints_smimea_flag(capsys) -> None:
    assert run(["example.com", "--record", "SMIMEA"]) == 1
    err = capsys.readouterr().err
    assert "--smimea" in err
    assert "opt-in" in err.lower() or "local-part" in err.lower()


def test_cli_rejects_reverse_with_smimea(capsys) -> None:
    assert run(["--reverse", "8.8.8.8", "--smimea", "alice"]) == 1
    assert "--reverse" in capsys.readouterr().err


@patch("cli.interface.DNSResolver")
def test_cli_smimea_prints_section(mock_resolver_cls, capsys) -> None:
    from analyzer.smimea import evaluate_smimea, smimea_query_name

    qname = smimea_query_name("example.com", "alice")
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    mock_resolver_cls.return_value.inspect_smimea.return_value = evaluate_smimea(
        qname,
        "alice",
        [DNSRecord("SMIMEA", qname, "3 1 1 assoc-length=32", 300)],
    )

    assert run(["example.com", "--record", "A", "--smimea", "alice"]) == 0
    output = capsys.readouterr().out
    assert "SMIMEA" in output
    assert "FOUND" in output
    assert "alice" in output
    assert "assoc-length=32" in output
    assert "SECURITY ANALYSIS" not in output
    mock_resolver_cls.return_value.inspect_smimea.assert_called_once_with(
        "example.com", "alice"
    )
    mock_resolver_cls.return_value.inspect_dnssec.assert_not_called()
    mock_resolver_cls.return_value.inspect_ipseckey.assert_not_called()


@patch("cli.interface.DNSResolver")
def test_cli_smimea_json_includes_observation(mock_resolver_cls, capsys) -> None:
    from analyzer.smimea import evaluate_smimea, smimea_query_name

    qname = smimea_query_name("example.com", "alice")
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    mock_resolver_cls.return_value.inspect_smimea.return_value = evaluate_smimea(
        qname,
        "alice",
        [DNSRecord("SMIMEA", qname, "3 1 1 assoc-length=32", 60)],
    )

    assert run(["example.com", "--smimea", "alice", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["smimea"][0]["status"] == "FOUND"
    assert data["smimea"][0]["local_part"] == "alice"
    assert data["smimea"][0]["associations"][0]["association_length"] == 32
    assert data["smimea"][0]["associations"][0]["usage"] == 3


def test_cli_help_lists_modes() -> None:
    help_text = build_parser().format_help()
    assert "--record" in help_text
    assert "--security" in help_text
    assert "--dkim" in help_text
    assert "--srv" in help_text
    assert "--naptr" in help_text
    assert "--uri" in help_text
    assert "--dname" in help_text
    assert "--ipseckey" in help_text
    assert "--smimea" in help_text
    assert "--all" in help_text
    assert "--reverse" in help_text
    assert "--format" in help_text
    assert "--output" in help_text
    assert "--config" in help_text
    assert "--nameserver" in help_text
    assert "--resolver" in help_text
    assert "--version" in help_text
    assert "not a vulnerability scanner" in help_text.lower()


def test_cli_help_exit_zero() -> None:
    with pytest.raises(SystemExit) as caught:
        run(["--help"])
    assert caught.value.code == 0


def test_cli_version_exits_zero(capsys) -> None:
    with pytest.raises(SystemExit) as caught:
        run(["--version"])
    assert caught.value.code == 0
    assert __version__ in capsys.readouterr().out


@patch("cli.interface.DNSResolver")
def test_cli_format_json_stdout(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )

    assert run(["example.com", "--format", "json"]) == 0
    captured = capsys.readouterr()
    assert "DNS ANALYZER" not in captured.out
    data = json.loads(captured.out)
    assert data["schema"] == "dns-analyzer.report.v1"
    assert data["target"] == "example.com"
    assert data["mode"] == "forward"
    assert data["records"][0]["value"] == "93.184.216.34"
    assert data["risk_score"]["band"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert data["security_analysis"]["findings"]
    assert data["dkim"] is None
    assert data["srv"] is None
    assert data["naptr"] is None
    assert data["uri"] is None
    assert data["dname"] is None
    assert data["ipseckey"] is None
    assert data["smimea"] is None
    assert data["mta_sts"]["query_name"] == "_mta-sts.example.com"
    assert data["tls_rpt"]["query_name"] == "_smtp._tls.example.com"
    assert data["bimi"]["query_name"] == "default._bimi.example.com"
    assert data["tlsa"]["query_name"] == "_443._tcp.example.com"
    assert data["sshfp"]["query_name"] == "example.com"
    assert data["fcrdns"]["checks"] == []
    assert data["mx_hosts"]["checks"] == []
    assert data["ns_hosts"]["checks"] == []
    assert data["cname_targets"]["checks"] == []
    assert data["soa_ns"]["status"] == "NOT DETECTED"
    assert data["caa"]["status"] == "NOT DETECTED"
    assert data["cds"]["status"] == "NOT DETECTED"
    assert data["cds"]["cds_found"] is False
    assert data["nsec"]["status"] == "NOT DETECTED"
    assert data["nsec"]["nsec_found"] is False
    assert data["csync"]["status"] == "NOT DETECTED"
    assert data["zonemd"]["status"] == "NOT DETECTED"
    assert data["rrsig"]["status"] == "NOT DETECTED"


@patch("cli.interface.DNSResolver")
def test_cli_format_csv_stdout(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            a=[DNSRecord("A", "example.com", "93.184.216.34", 60)],
            mx=[DNSRecord("MX", "example.com", "mail.example.com", 300, priority=10)],
        ),
    )

    assert run(["example.com", "--format", "csv", "--record", "A"]) == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("record_type,name,value,ttl,priority")
    assert "93.184.216.34" in captured.out
    assert "mail.example.com" not in captured.out
    assert "DNS ANALYZER" not in captured.out
    mock_resolver_cls.return_value.inspect_dnssec.assert_not_called()
    mock_resolver_cls.return_value.inspect_cds.assert_not_called()
    mock_resolver_cls.return_value.inspect_nsec.assert_not_called()
    mock_resolver_cls.return_value.inspect_csync.assert_not_called()
    mock_resolver_cls.return_value.inspect_zonemd.assert_not_called()
    mock_resolver_cls.return_value.inspect_rrsig.assert_not_called()
    mock_resolver_cls.return_value.lookup_core.assert_called_once_with(
        "example.com", types=("A",)
    )


@patch("cli.interface.DNSResolver")
def test_cli_format_html_stdout(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(
            a=[DNSRecord("A", "example.com", "93.184.216.34", 60)],
            txt=[DNSRecord("TXT", "example.com", "<script>alert(1)</script>", 60)],
        ),
    )

    assert run(["example.com", "--format", "html", "--record", "A", "--record", "TXT"]) == 0
    captured = capsys.readouterr()
    assert "DNS ANALYZER" not in captured.out
    assert captured.out.startswith("<!DOCTYPE html>")
    assert "not a vulnerability scanner" in captured.out.lower()
    assert "<script>" not in captured.out
    assert "&lt;script&gt;" in captured.out
    assert "93.184.216.34" in captured.out


@patch("cli.interface.DNSResolver")
def test_cli_output_json_file_keeps_human(mock_resolver_cls, tmp_path: Path, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    path = tmp_path / "example.json"

    assert run(["example.com", "--output", str(path)]) == 0
    captured = capsys.readouterr()
    assert "DNS ANALYZER" in captured.out
    assert f"Wrote {path}" in captured.err
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["target"] == "example.com"
    assert data["records"][0]["record_type"] == "A"


@patch("cli.interface.DNSResolver")
def test_cli_format_json_output_file_skips_human(mock_resolver_cls, tmp_path: Path, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )
    path = tmp_path / "only.json"

    assert run(["example.com", "--format", "json", "--output", str(path)]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Wrote" in captured.err
    assert json.loads(path.read_text(encoding="utf-8"))["mode"] == "forward"


@patch("cli.interface.DNSResolver")
def test_cli_reverse_format_json(mock_resolver_cls, capsys) -> None:
    mock_resolver_cls.return_value.resolve_reverse.return_value = [
        DNSRecord("PTR", "8.8.8.8.in-addr.arpa", "dns.google", 86400),
    ]

    assert run(["--reverse", "8.8.8.8", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["mode"] == "reverse"
    assert data["target"] == "8.8.8.8"
    assert data["ptr_query"] == "8.8.8.8.in-addr.arpa"
    assert data["records"][0]["value"] == "dns.google"
    assert data["security_analysis"] is None


def test_cli_rejects_output_txt_in_text_mode(capsys) -> None:
    assert run(["example.com", "--output", "out.txt"]) == 1
    assert ".json, .csv, or .html" in capsys.readouterr().err


def test_cli_rejects_format_output_mismatch(capsys) -> None:
    assert run(["example.com", "--format", "json", "--output", "out.csv"]) == 1
    assert "does not match" in capsys.readouterr().err


def test_cli_usage_without_domain(capsys) -> None:
    assert run([]) == 0
    assert "Usage:" in capsys.readouterr().out


def test_cli_rejects_domain_and_reverse(capsys) -> None:
    assert run(["example.com", "--reverse", "8.8.8.8"]) == 1
    assert "not both" in capsys.readouterr().err


def test_cli_rejects_invalid_reverse_ip(capsys) -> None:
    assert run(["--reverse", "not-an-ip"]) == 1
    assert "Invalid IP" in capsys.readouterr().err


@patch("cli.interface.DNSResolver")
def test_cli_nxdomain_exits_one(mock_resolver_cls, capsys) -> None:
    mock_resolver_cls.return_value.lookup_core.side_effect = DomainNotFoundError()
    assert run(["missing.example"]) == 1
    assert "does not exist" in capsys.readouterr().err
    mock_resolver_cls.return_value.inspect_dnssec.assert_not_called()
    mock_resolver_cls.return_value.inspect_cds.assert_not_called()
    mock_resolver_cls.return_value.inspect_nsec.assert_not_called()
    mock_resolver_cls.return_value.inspect_csync.assert_not_called()
    mock_resolver_cls.return_value.inspect_zonemd.assert_not_called()
    mock_resolver_cls.return_value.inspect_rrsig.assert_not_called()


@patch("cli.interface.DNSResolver")
def test_cli_timeout_exits_one(mock_resolver_cls, capsys) -> None:
    mock_resolver_cls.return_value.lookup_core.side_effect = DNSTimeoutError()
    assert run(["example.com"]) == 1
    err = capsys.readouterr().err
    assert "timed out" in err
    assert "Traceback" not in err


@patch("cli.interface.DNSResolver")
def test_cli_network_error_exits_one(mock_resolver_cls, capsys) -> None:
    from analyzer.exceptions import DNSNetworkError

    mock_resolver_cls.return_value.lookup_core.side_effect = DNSNetworkError()
    assert run(["example.com"]) == 1
    err = capsys.readouterr().err
    assert "Network error while querying DNS" in err
    assert "Traceback" not in err


def test_cli_rejects_non_positive_timeout(capsys) -> None:
    assert run(["example.com", "--timeout", "0"]) == 1
    assert "positive" in capsys.readouterr().err


def test_cli_rejects_huge_timeout(capsys) -> None:
    assert run(["example.com", "--timeout", "999"]) == 1
    assert "120" in capsys.readouterr().err


@patch("cli.interface._run", side_effect=RuntimeError("boom"))
def test_cli_unexpected_error_has_no_traceback(mock_run, capsys) -> None:
    assert run(["example.com"]) == 1
    err = capsys.readouterr().err
    assert "Unexpected failure" in err
    assert "Traceback" not in err
    assert "boom" not in err


@patch("cli.interface._run", side_effect=KeyboardInterrupt)
def test_cli_interrupt_exits_130(mock_run, capsys) -> None:
    assert run(["example.com"]) == 130
    assert "Interrupted" in capsys.readouterr().err


def test_plan_export_text_is_human_only() -> None:
    plan = plan_export("text", None)
    assert isinstance(plan, ExportPlan)
    assert plan.print_human is True
    assert plan.file_format is None
    assert plan.path is None


def test_plan_export_json_stdout() -> None:
    plan = plan_export("json", None)
    assert isinstance(plan, ExportPlan)
    assert plan.print_human is False
    assert plan.file_format == "json"
    assert plan.path is None


def test_plan_export_html_stdout() -> None:
    plan = plan_export("html", None)
    assert isinstance(plan, ExportPlan)
    assert plan.print_human is False
    assert plan.file_format == "html"
    assert plan.path is None


def test_plan_export_text_html_file() -> None:
    plan = plan_export("text", "reports/out.html")
    assert isinstance(plan, ExportPlan)
    assert plan.print_human is True
    assert plan.file_format == "html"


def test_types_to_query_default_is_all() -> None:
    view = ReportView(record_types=None, show_security=True)
    assert types_to_query(view) is None


def test_types_to_query_record_mx_includes_a() -> None:
    view = ReportView(record_types=frozenset({"MX"}), show_security=False)
    assert types_to_query(view) == ("A", "MX")


def test_types_to_query_record_a_only() -> None:
    view = ReportView(record_types=frozenset({"A"}), show_security=False)
    assert types_to_query(view) == ("A",)


def test_types_to_query_security_skips_mx_ns_soa_https() -> None:
    view = ReportView(record_types=frozenset(), show_security=True)
    assert types_to_query(view) == ("A", "AAAA", "CNAME", "TXT", "CAA")
    assert "HTTPS" not in types_to_query(view)
    assert "SVCB" not in types_to_query(view)


def test_types_to_query_record_plus_security() -> None:
    view = ReportView(record_types=frozenset({"MX"}), show_security=True)
    assert types_to_query(view) == ("A", "AAAA", "CNAME", "MX", "TXT", "CAA")


def test_cli_rejects_config_with_nameserver(capsys) -> None:
    assert run(["example.com", "--config", "x.json", "--nameserver", "192.0.2.1"]) == 1
    assert "either --config or --nameserver" in capsys.readouterr().err


def test_cli_resolver_requires_config(capsys) -> None:
    assert run(["example.com", "--resolver", "lab"]) == 1
    assert "--config" in capsys.readouterr().err


def test_cli_config_missing_file(tmp_path: Path, capsys) -> None:
    missing = tmp_path / "nope.json"
    assert run(["example.com", "--config", str(missing)]) == 1
    assert "Could not read" in capsys.readouterr().err


@patch("cli.interface.DNSResolver")
def test_cli_nameserver_overrides_os_resolver(mock_resolver_cls, capsys) -> None:
    _bind(
        mock_resolver_cls,
        _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)]),
    )

    assert run(["example.com", "--nameserver", "192.0.2.53", "--record", "A"]) == 0
    mock_resolver_cls.assert_called_with(timeout=5.0, nameservers=["192.0.2.53"])
    output = capsys.readouterr().out
    assert "Resolver:" in output
    assert "cli" in output
    assert "RESOLVER COMPARISON" not in output


@patch("cli.interface.DNSResolver")
def test_cli_config_reports_inconsistent_a(mock_resolver_cls, tmp_path: Path, capsys) -> None:
    path = tmp_path / "resolvers.json"
    path.write_text(
        json.dumps(
            {
                "resolvers": [
                    {"name": "system", "nameservers": []},
                    {"name": "lab", "nameservers": ["192.0.2.53"]},
                ]
            }
        ),
        encoding="utf-8",
    )
    primary = _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)])
    extra = _lookup(a=[DNSRecord("A", "example.com", "198.51.100.10", 60)])
    mock_resolver_cls.return_value.lookup_core.side_effect = [primary, extra]

    assert run(["example.com", "--config", str(path), "--record", "A"]) == 0
    output = capsys.readouterr().out
    assert "RESOLVER COMPARISON" in output
    assert "INCONSISTENT" in output
    assert "Potential DNS inconsistency" in output
    assert "hijacking" in output.lower()
    assert mock_resolver_cls.return_value.lookup_core.call_count == 2
    assert mock_resolver_cls.call_args_list[0].kwargs["nameservers"] is None
    assert mock_resolver_cls.call_args_list[1].kwargs["nameservers"] == ["192.0.2.53"]


@patch("cli.interface.DNSResolver")
def test_cli_extra_resolver_timeout_is_incomplete(
    mock_resolver_cls, tmp_path: Path, capsys
) -> None:
    path = tmp_path / "resolvers.json"
    path.write_text(
        json.dumps(
            {
                "resolvers": [
                    {"name": "system", "nameservers": []},
                    {"name": "lab", "nameservers": ["192.0.2.53"]},
                ]
            }
        ),
        encoding="utf-8",
    )
    primary = _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)])
    mock_resolver_cls.return_value.lookup_core.side_effect = [primary, DNSTimeoutError()]

    assert run(["example.com", "--config", str(path), "--record", "A"]) == 0
    output = capsys.readouterr().out
    assert "INCOMPLETE" in output
    assert "DNS query timed out" in output


@patch("cli.interface.DNSResolver")
def test_cli_json_includes_resolver_comparison(
    mock_resolver_cls, tmp_path: Path, capsys
) -> None:
    path = tmp_path / "resolvers.json"
    path.write_text(
        json.dumps(
            {
                "resolvers": [
                    {"name": "system", "nameservers": []},
                    {"name": "lab", "nameservers": ["192.0.2.53"]},
                ]
            }
        ),
        encoding="utf-8",
    )
    lookup = _lookup(a=[DNSRecord("A", "example.com", "93.184.216.34", 60)])
    mock_resolver_cls.return_value.lookup_core.side_effect = [lookup, lookup]

    assert run(["example.com", "--config", str(path), "--record", "A", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["resolver_comparison"]["status"] == "CONSISTENT"
    assert data["resolver_comparison"]["primary"] == "system"
    assert data["resolver_comparison"]["resolvers"][1]["name"] == "lab"
