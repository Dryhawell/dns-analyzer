"""DNSSEC observation tests. No network access."""

from unittest.mock import MagicMock

import dns.exception
import dns.flags
import dns.resolver

from analyzer.dnssec import evaluate_dnssec
from analyzer.resolver import DNSResolver


def test_evaluate_not_detected_without_keys() -> None:
    observation = evaluate_dnssec(dnskey_found=False, ds_found=False, ad_flag=False)
    assert observation.status == "NOT DETECTED"
    assert "compromised" in observation.note


def test_evaluate_detected_with_dnskey_only() -> None:
    observation = evaluate_dnssec(dnskey_found=True, ds_found=False, ad_flag=False)
    assert observation.status == "DETECTED"
    assert observation.dnskey_found is True
    assert observation.ds_found is False


def test_evaluate_detected_with_ds() -> None:
    observation = evaluate_dnssec(dnskey_found=False, ds_found=True, ad_flag=True)
    assert observation.status == "DETECTED"
    assert observation.ad_flag is True


def test_inspect_dnssec_uses_probe_results() -> None:
    resolver = DNSResolver(timeout=1.0)
    resolver._dnssec_probe = MagicMock(side_effect=[(True, False), (True, True)])  # type: ignore[method-assign]

    observation = resolver.inspect_dnssec("example.com")

    assert observation.status == "DETECTED"
    assert observation.dnskey_found is True
    assert observation.ds_found is True
    assert observation.ad_flag is True


def test_dnssec_probe_timeout_is_not_found() -> None:
    resolver = DNSResolver(timeout=1.0)
    client = MagicMock()
    client.resolve.side_effect = dns.exception.Timeout()
    errors: list[str] = []

    found, ad_flag = resolver._dnssec_probe(client, "example.com", "DNSKEY", errors)

    assert found is False
    assert ad_flag is False
    assert errors == ["DNSKEY query timed out"]


def test_dnssec_probe_reads_ad_flag() -> None:
    resolver = DNSResolver(timeout=1.0)
    answer = MagicMock()
    answer.response.flags = dns.flags.AD
    client = MagicMock()
    client.resolve.return_value = answer

    found, ad_flag = resolver._dnssec_probe(client, "example.com", "DS", [])

    assert found is True
    assert ad_flag is True
    client.resolve.assert_called_once_with("example.com", "DS", search=False)


def test_dnssec_probe_noanswer() -> None:
    resolver = DNSResolver(timeout=1.0)
    client = MagicMock()
    client.resolve.side_effect = dns.resolver.NoAnswer(
        response=type("R", (), {"question": "example.com IN DNSKEY"})()
    )
    errors: list[str] = []

    found, ad_flag = resolver._dnssec_probe(client, "example.com", "DNSKEY", errors)

    assert found is False
    assert ad_flag is False
    assert errors == []
