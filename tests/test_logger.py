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