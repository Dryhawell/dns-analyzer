"""SPF parsing tests. No network access."""

from analyzer.models import DNSRecord
from analyzer.spf import inspect_spf


def _txt(*values: str) -> tuple[DNSRecord, ...]:
    return tuple(DNSRecord("TXT", "example.com", value, 300) for value in values)


def test_spf_found_softfail() -> None:
    observation = inspect_spf(_txt("v=spf1 include:_spf.google.com ~all"))
    assert observation.status == "FOUND"
    assert observation.all_term == "~all"
    assert observation.multiple_records is False
    assert "softfail" in (observation.all_meaning or "")


def test_spf_found_fail() -> None:
    observation = inspect_spf(_txt("v=spf1 -all"))
    assert observation.all_term == "-all"
    assert "reject" in (observation.all_meaning or "")


def test_spf_not_detected_without_policy() -> None:
    observation = inspect_spf(_txt("google-site-verification=abc"))
    assert observation.status == "NOT DETECTED"
    assert observation.policies == ()


def test_spf_not_detected_when_txt_timed_out() -> None:
    observation = inspect_spf((), errors=(("TXT", "DNS query timed out."),))
    assert observation.status == "NOT DETECTED"
    assert observation.error is not None
    assert "timed out" in observation.error


def test_spf_ignores_include_host_named_all() -> None:
    observation = inspect_spf(_txt("v=spf1 include:all.example.net -all"))
    assert observation.all_term == "-all"


def test_multiple_spf_records() -> None:
    observation = inspect_spf(_txt("v=spf1 -all", "v=spf1 +all"))
    assert observation.status == "FOUND"
    assert observation.multiple_records is True
    assert observation.all_term == "+all"


def test_spf_plus_all_and_bare_all() -> None:
    plus = inspect_spf(_txt("v=spf1 +all"))
    assert plus.all_term == "+all"
    assert "unusual" in (plus.all_meaning or "")
    bare = inspect_spf(_txt("v=spf1 all"))
    assert bare.all_term == "all"


def test_spf_neutral_all() -> None:
    observation = inspect_spf(_txt("v=spf1 mx ?all"))
    assert observation.all_term == "?all"
    assert "neutral" in (observation.all_meaning or "")


def test_spf_case_insensitive_prefix() -> None:
    observation = inspect_spf(_txt("V=SPF1 mx ~all"))
    assert observation.status == "FOUND"
    assert observation.all_term == "~all"


def test_include_domains_keeps_underscore_labels() -> None:
    from analyzer.spf import include_domains, redirect_domain

    assert include_domains("v=spf1 include:_spf.google.com include:spf.example.net -all") == (
        "_spf.google.com",
        "spf.example.net",
    )
    assert redirect_domain("v=spf1 redirect=_spf.example.net") == "_spf.example.net"
    assert include_domains("v=spf1 include:%{i}._spf.example.net -all") == ()


def test_expand_spf_one_hop_does_not_follow_nested() -> None:
    from analyzer.spf import expand_spf, inspect_spf

    queried: list[str] = []

    def fetch(name: str):
        queried.append(name)
        if name == "_spf.google.com":
            return (
                (DNSRecord("TXT", name, "v=spf1 include:_netblocks.google.com ~all", 300),),
                None,
            )
        raise AssertionError(f"unexpected lookup {name}")

    observation = expand_spf(
        inspect_spf(_txt("v=spf1 include:_spf.google.com ~all")),
        fetch,
    )
    assert queried == ["_spf.google.com"]
    assert len(observation.hops) == 1
    hop = observation.hops[0]
    assert hop.kind == "include"
    assert hop.status == "FOUND"
    assert hop.nested_includes == ("_netblocks.google.com",)
    assert "~all" in (hop.all_term or "")


def test_expand_spf_timeout_is_unreadable_hop() -> None:
    from analyzer.spf import expand_spf, inspect_spf

    def fetch(name: str):
        return (), "DNS query timed out."

    observation = expand_spf(
        inspect_spf(_txt("v=spf1 include:_spf.example.net -all")),
        fetch,
    )
    assert observation.hops[0].status == "NOT DETECTED"
    assert observation.hops[0].error is not None
    assert observation.status == "FOUND"


def test_expand_spf_missing_include_policy() -> None:
    from analyzer.spf import expand_spf, inspect_spf

    def fetch(name: str):
        return (), None

    observation = expand_spf(
        inspect_spf(_txt("v=spf1 include:missing.example.net -all")),
        fetch,
    )
    assert observation.hops[0].status == "NOT DETECTED"
    assert observation.hops[0].error is None
