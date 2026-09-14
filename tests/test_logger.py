"""Logging tests. No network access."""

from pathlib import Path
from unittest.mock import patch

from analyzer.models import DNSRecord
from cli.interface import run
from utils.logger import configure_logging, get_logger, reset_logging


def _bind_lookup(mock_cls) -> None:
    from analyzer.dmarc import evaluate_dmarc
    from analyzer.dnssec import evaluate_dnssec
    from analyzer.models import CoreLookup
    from analyzer.bimi import evaluate_bimi
    from analyzer.fcrdns import evaluate_fcrdns
    from analyzer.mx import evaluate_mx_hosts
    from analyzer.ns import evaluate_ns_hosts
    from analyzer.cname import evaluate_cname_targets
    from analyzer.soa import evaluate_soa_ns
    from analyzer.caa import evaluate_caa
    from analyzer.cds import evaluate_cds
    from analyzer.sshfp import evaluate_sshfp
    from analyzer.tlsa import evaluate_tlsa
    from analyzer.mtasts import evaluate_mta_sts
    from analyzer.tlsrpt import evaluate_tls_rpt

    mock_cls.return_value.lookup_core.return_value = CoreLookup(
        a=(DNSRecord("A", "example.com", "93.184.216.34", 60),),
        aaaa=(),
        cname=(),
        mx=(),
        ns=(),
        txt=(),
        soa=(),
        caa=(),
    )
    mock_cls.return_value.inspect_dnssec.return_value = evaluate_dnssec(
        dnskey_found=False, ds_found=False, ad_flag=False
    )
    mock_cls.return_value.inspect_dmarc.return_value = evaluate_dmarc(
        "_dmarc.example.com", ()
    )
    mock_cls.return_value.inspect_mta_sts.return_value = evaluate_mta_sts(
        "_mta-sts.example.com", "mta-sts.example.com", ()
    )
    mock_cls.return_value.inspect_tls_rpt.return_value = evaluate_tls_rpt(
        "_smtp._tls.example.com", ()
    )
    mock_cls.return_value.inspect_bimi.return_value = evaluate_bimi(
        "default._bimi.example.com", "default", ()
    )
    mock_cls.return_value.inspect_tlsa.return_value = evaluate_tlsa(
        "_443._tcp.example.com", ()
    )
    mock_cls.return_value.inspect_sshfp.return_value = evaluate_sshfp(
        "example.com", ()
    )
    mock_cls.return_value.inspect_fcrdns.return_value = evaluate_fcrdns(())
    mock_cls.return_value.inspect_mx_hosts.return_value = evaluate_mx_hosts(
        "example.com", ()
    )
    mock_cls.return_value.inspect_ns_hosts.return_value = evaluate_ns_hosts(
        "example.com", ()
    )
    mock_cls.return_value.inspect_cname_targets.return_value = evaluate_cname_targets(())
    mock_cls.return_value.inspect_soa_ns.return_value = evaluate_soa_ns(
        "example.com", None, ()
    )
    mock_cls.return_value.inspect_caa.return_value = evaluate_caa("example.com", ())
    mock_cls.return_value.inspect_cds.return_value = evaluate_cds(
        "example.com", cds_found=False, cdnskey_found=False
    )
    mock_cls.return_value.expand_spf.side_effect = lambda obs: obs


def test_configure_logging_writes_info_to_file(tmp_path: Path) -> None:
    reset_logging()
    path = tmp_path / "dns-analyzer.log"
    try:
        configure_logging(path)
        get_logger("cli").info("DNS analysis started target=%s", "example.com")
        text = path.read_text(encoding="utf-8")
    finally:
        reset_logging()
    assert "INFO" in text
    assert "DNS analysis started target=example.com" in text
    assert "dns_analyzer.cli" in text


def test_invalid_domain_is_logged_without_raw_input(tmp_path: Path) -> None:
    reset_logging()
    path = tmp_path / "dns-analyzer.log"
    try:
        configure_logging(path)
        assert run(["???"]) == 1
        text = path.read_text(encoding="utf-8")
    finally:
        reset_logging()
    assert "Invalid domain" in text
    assert "ERROR" in text
    assert "???" not in text


@patch("cli.interface.DNSResolver")
def test_analysis_log_omits_record_values(mock_cls, tmp_path: Path, capsys) -> None:
    reset_logging()
    path = tmp_path / "dns-analyzer.log"
    try:
        configure_logging(path)
        _bind_lookup(mock_cls)
        assert run(["example.com", "--format", "json"]) == 0
        text = path.read_text(encoding="utf-8")
    finally:
        reset_logging()

    assert "DNS analysis started target=example.com" in text
    assert "DNS analysis finished" in text
    assert "93.184.216.34" not in text
    assert "token=" not in text
    out = capsys.readouterr().out
    assert out.lstrip().startswith("{")