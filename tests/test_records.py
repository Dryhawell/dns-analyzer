"""Tests for rdata formatting. No network access."""

from analyzer.records import format_rdata


class DummyRdata:
    def __init__(self, text: str, **attrs: object) -> None:
        self._text = text
        for key, value in attrs.items():
            setattr(self, key, value)

    def __str__(self) -> str:
        return self._text


def test_a_record_strips_nothing_extra() -> None:
    assert format_rdata("A", DummyRdata("93.184.216.34")) == "93.184.216.34"


def test_ns_strips_trailing_dot() -> None:
    assert format_rdata("NS", DummyRdata("ns1.example.com.")) == "ns1.example.com"


def test_mx_value_includes_priority() -> None:
    rdata = DummyRdata("10 mail.example.com.", preference=10, exchange="mail.example.com.")
    assert format_rdata("MX", rdata) == "10 mail.example.com"


def test_caa_quotes_value() -> None:
    rdata = DummyRdata("unused", flags=0, tag="issue", value="letsencrypt.org")
    assert format_rdata("CAA", rdata) == '0 issue "letsencrypt.org"'


def test_soa_includes_serial() -> None:
    rdata = DummyRdata(
        "unused",
        mname="ns1.example.com.",
        rname="hostmaster.example.com.",
        serial=2026090201,
    )
    assert format_rdata("SOA", rdata) == "ns1.example.com hostmaster.example.com serial=2026090201"
