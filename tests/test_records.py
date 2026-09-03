"""Tests for rdata formatting. No network access."""

from analyzer.records import describe_ip_scope, format_rdata, records_from_answer


class SimpleAnswer:
    def __init__(self, *rdata: object, ttl: int = 300) -> None:
        self._rdata = rdata
        self.ttl = ttl

    def __iter__(self):
        return iter(self._rdata)


class DummyRdata:
    def __init__(self, text: str, **attrs: object) -> None:
        self._text = text
        for key, value in attrs.items():
            setattr(self, key, value)

    def __str__(self) -> str:
        return self._text


def test_aaaa_compresses_ipv6() -> None:
    expanded = DummyRdata("2001:0db8:0000:0000:0000:0000:0000:0001")
    assert format_rdata("AAAA", expanded) == "2001:db8::1"


def test_describe_ip_scope_global_is_silent() -> None:
    assert describe_ip_scope("93.184.216.34") is None
    assert describe_ip_scope("2001:db8::1") == "private"


def test_describe_ip_scope_loopback_and_private() -> None:
    assert describe_ip_scope("127.0.0.1") == "loopback"
    assert describe_ip_scope("192.168.0.1") == "private"
    assert describe_ip_scope("::1") == "loopback"


def test_ns_strips_trailing_dot() -> None:
    assert format_rdata("NS", DummyRdata("ns1.example.com.")) == "ns1.example.com"


def test_mx_value_is_exchange_only() -> None:
    rdata = DummyRdata("10 mail.example.com.", preference=10, exchange="mail.example.com.")
    assert format_rdata("MX", rdata) == "mail.example.com"


def test_caa_quotes_value() -> None:
    rdata = DummyRdata("unused", flags=0, tag="issue", value="letsencrypt.org")
    assert format_rdata("CAA", rdata) == '0 issue "letsencrypt.org"'


def test_caa_details_explain_issue_tags() -> None:
    issue = DummyRdata("unused", flags=0, tag="issue", value="letsencrypt.org")
    wild = DummyRdata("unused", flags=0, tag=b"issuewild", value=b"letsencrypt.org")
    iodef = DummyRdata("unused", flags=0, tag="iodef", value="mailto:caa@example.com")
    other = DummyRdata("unused", flags=0, tag="unknown", value="x")

    issue_row = records_from_answer("CAA", "Example.COM.", SimpleAnswer(issue, ttl=3600))[0]
    assert issue_row.name == "example.com"
    assert "allows this CA to issue certificates" in dict(issue_row.details)["Tag"]

    wild_row = records_from_answer("CAA", "example.com", SimpleAnswer(wild))[0]
    assert wild_row.value == '0 issuewild "letsencrypt.org"'
    assert "wildcard" in dict(wild_row.details)["Tag"]

    iodef_row = records_from_answer("CAA", "example.com", SimpleAnswer(iodef))[0]
    assert "incident report" in dict(iodef_row.details)["Tag"]

    other_row = records_from_answer("CAA", "example.com", SimpleAnswer(other))[0]
    assert other_row.details == ()


def test_txt_joins_byte_fragments() -> None:
    rdata = DummyRdata("unused", strings=(b"v=spf1 ", b"-all"))
    assert format_rdata("TXT", rdata) == "v=spf1 -all"


def test_describe_ip_scope_other_non_global() -> None:
    assert describe_ip_scope("169.254.1.1") == "link-local"
    assert describe_ip_scope("0.0.0.0") == "unspecified"
    assert describe_ip_scope("224.0.0.1") == "multicast"
    assert describe_ip_scope("not-an-ip") == "invalid"


def test_soa_details_include_mailbox_and_timers() -> None:
    rdata = DummyRdata(
        "unused",
        mname="ns1.example.com.",
        rname="hostmaster.example.com.",
        serial=2026090201,
        refresh=7200,
        retry=1800,
        expire=1209600,
        minimum=3600,
    )
    assert format_rdata("SOA", rdata) == "ns1.example.com serial=2026090201"
    records = records_from_answer("SOA", "example.com", [rdata])
    details = dict(records[0].details)
    assert details["Primary NS"] == "ns1.example.com"
    assert details["Mailbox"] == "hostmaster.example.com"
    assert details["Serial"] == "2026090201"
    assert details["Refresh"] == "7200"
