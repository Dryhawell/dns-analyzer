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
    assert describe_ip_scope("2001:db8::1") == "documentation"


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
    assert describe_ip_scope("192.0.2.1") == "documentation"
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


def test_https_service_mode_summarizes_params() -> None:
    class _Param:
        def __init__(self, text: str) -> None:
            self._text = text

        def to_text(self) -> str:
            return self._text

    rdata = DummyRdata(
        "unused",
        priority=1,
        target=".",
        params={"alpn": _Param("h2,h3"), "port": _Param("443"), "ech": _Param("QUFB")},
    )
    assert format_rdata("HTTPS", rdata) == "1 . alpn=h2,h3 port=443 ech=(present)"
    row = records_from_answer("HTTPS", "example.com", SimpleAnswer(rdata, ttl=60))[0]
    assert row.priority == 1
    details = dict(row.details)
    assert "ServiceMode" in details["Mode"]
    assert "h2,h3" in details["ALPN"]
    assert details["Port"] == "443"
    assert "present" in details["ECH"]
    assert "QUFB" not in row.value
    assert "QUFB" not in details["ECH"]


def test_https_alias_mode() -> None:
    rdata = DummyRdata("unused", priority=0, target="svc.example.net.")
    assert format_rdata("HTTPS", rdata) == "0 svc.example.net"
    row = records_from_answer("SVCB", "example.com", SimpleAnswer(rdata))[0]
    assert "AliasMode" in dict(row.details)["Mode"]
    assert row.record_type == "SVCB"


def test_https_from_dnspython_rdata() -> None:
    import dns.rdata

    rdata = dns.rdata.from_text("IN", "HTTPS", "1 . alpn=h2,h3 port=443")
    text = format_rdata("HTTPS", rdata)
    assert text.startswith("1 .")
    assert "alpn=" in text
    assert "h2" in text
    assert "port=443" in text


def test_srv_value_is_priority_weight_port_target() -> None:
    rdata = DummyRdata(
        "unused",
        priority=10,
        weight=5,
        port=5060,
        target="sip.example.com.",
    )
    assert format_rdata("SRV", rdata) == "10 5 5060 sip.example.com"
    row = records_from_answer("SRV", "_sip._tcp.Example.COM.", SimpleAnswer(rdata, ttl=60))[0]
    assert row.name == "_sip._tcp.example.com"
    assert row.priority == 10
    details = dict(row.details)
    assert "lower number" in details["Priority"]
    assert details["Port"] == "5060"
    assert details["Target"] == "sip.example.com"


def test_srv_dot_target_explains_not_offered() -> None:
    rdata = DummyRdata("unused", priority=0, weight=0, port=0, target=".")
    assert format_rdata("SRV", rdata) == "0 0 0 ."
    row = records_from_answer("SRV", "_sip._tcp.example.com", SimpleAnswer(rdata))[0]
    assert "not offered" in dict(row.details)["Note"]


def test_naptr_value_lists_fields() -> None:
    rdata = DummyRdata(
        "unused",
        order=100,
        preference=50,
        flags="u",
        service="E2U+sip",
        regexp="!^.*$!sip:info@example.com!",
        replacement=".",
    )
    assert (
        format_rdata("NAPTR", rdata)
        == '100 50 "u" "E2U+sip" "!^.*$!sip:info@example.com!" .'
    )
    row = records_from_answer("NAPTR", "Example.COM.", SimpleAnswer(rdata, ttl=60))[0]
    assert row.name == "example.com"
    assert row.priority == 100
    details = dict(row.details)
    assert details["Services"] == "E2U+sip"
    assert "does not rewrite" in details["Flags"]
    assert "not executed" in details["Note"]


def test_naptr_bytes_fields_and_dot_replacement() -> None:
    rdata = DummyRdata(
        "unused",
        order=10,
        preference=20,
        flags=b"s",
        service=b"SIP+D2T",
        regexp=b"",
        replacement="sip.example.com.",
    )
    assert format_rdata("NAPTR", rdata) == '10 20 "s" "SIP+D2T" "" sip.example.com'
    row = records_from_answer("NAPTR", "example.com", SimpleAnswer(rdata))[0]
    assert dict(row.details)["Replacement"] == "sip.example.com"


def test_uri_value_lists_fields() -> None:
    rdata = DummyRdata(
        "unused",
        priority=10,
        weight=1,
        target="https://www.example.com/path",
    )
    assert format_rdata("URI", rdata) == '10 1 "https://www.example.com/path"'
    row = records_from_answer("URI", "Example.COM.", SimpleAnswer(rdata, ttl=60))[0]
    assert row.name == "example.com"
    assert row.priority == 10
    details = dict(row.details)
    assert details["Target"] == "https://www.example.com/path"
    assert "does not fetch" in details["Scheme"]
    assert "not fetched" in details["Note"]


def test_uri_bytes_target() -> None:
    rdata = DummyRdata(
        "unused",
        priority=20,
        weight=5,
        target=b"ftp://ftp.example.com/pub",
    )
    assert format_rdata("URI", rdata) == '20 5 "ftp://ftp.example.com/pub"'
    row = records_from_answer("URI", "example.com", SimpleAnswer(rdata))[0]
    assert dict(row.details)["Target"] == "ftp://ftp.example.com/pub"
