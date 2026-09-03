"""TTL helpers. No network access."""

from analyzer.models import DNSRecord
from analyzer.ttl import describe_cache, format_duration, format_ttl_line, summarize_ttls


def test_format_duration_buckets() -> None:
    assert format_duration(45) == "45s"
    assert format_duration(300) == "300s (5m)"
    assert format_duration(3600) == "3600s (1h)"
    assert format_duration(86400) == "86400s (1d)"
    assert format_duration(-5) == "0s"
    assert "~" in format_duration(90)
    assert "~" in format_duration(3700)


def test_describe_cache_is_not_a_security_rating() -> None:
    assert "secure" not in describe_cache(30).lower()
    assert "insecure" not in describe_cache(86400).lower()
    assert "very short" in describe_cache(30)
    assert "long cache" in describe_cache(7200)


def test_summarize_ttls_tracks_shortest_and_longest() -> None:
    records = (
        DNSRecord("A", "example.com", "1.1.1.1", 60),
        DNSRecord("NS", "example.com", "ns1.example.com", 86400),
        DNSRecord("MX", "example.com", "mail.example.com", 60, priority=10),
    )
    summary = summarize_ttls(records)
    assert summary is not None
    assert summary.shortest == 60
    assert summary.longest == 86400
    assert summary.shortest_types == ("A", "MX")
    assert summary.longest_types == ("NS",)
    assert summary.record_count == 3


def test_summarize_empty() -> None:
    assert summarize_ttls([]) is None


def test_format_ttl_line() -> None:
    assert format_ttl_line(3600) == "TTL: 3600s (1h)"
