"""Resolver JSON config. No network access."""

import json
from pathlib import Path

import pytest

from analyzer.config import (
    load_resolver_file,
    os_default_settings,
    select_resolvers,
    settings_from_nameservers,
)
from analyzer.exceptions import ResolverConfigError

_EXAMPLE = Path(__file__).resolve().parents[1] / "config" / "resolvers.example.json"


def _write(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_os_default_uses_empty_nameservers() -> None:
    settings = os_default_settings()
    assert settings.primary.name == "system"
    assert settings.primary.nameservers == ()
    assert settings.extras == ()


def test_example_config_loads() -> None:
    settings = load_resolver_file(_EXAMPLE)
    assert settings.delay_seconds == 0
    assert settings.profiles[0].name == "system"
    assert settings.profiles[0].nameservers == ()
    assert settings.profiles[1].name == "secondary"
    assert settings.profiles[1].nameservers == ("203.0.113.53",)


def test_load_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ResolverConfigError, match="Could not read"):
        load_resolver_file(tmp_path / "missing.json")


def test_load_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ResolverConfigError, match="valid JSON"):
        load_resolver_file(path)


def test_load_rejects_duplicate_names(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "dup.json",
        {
            "resolvers": [
                {"name": "a", "nameservers": []},
                {"name": "a", "nameservers": ["192.0.2.1"]},
            ]
        },
    )
    with pytest.raises(ResolverConfigError, match="Duplicate"):
        load_resolver_file(path)


def test_load_rejects_invalid_ip(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "ip.json",
        {"resolvers": [{"name": "x", "nameservers": ["not-an-ip"]}]},
    )
    with pytest.raises(ResolverConfigError, match="Invalid IP"):
        load_resolver_file(path)


def test_select_resolvers_keeps_flag_order(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "ok.json",
        {
            "resolvers": [
                {"name": "system", "nameservers": []},
                {"name": "office", "nameservers": ["192.0.2.53"]},
                {"name": "lab", "nameservers": ["198.51.100.53"]},
            ]
        },
    )
    loaded = load_resolver_file(path)
    picked = select_resolvers(loaded, ["lab", "system"])
    assert [item.name for item in picked.profiles] == ["lab", "system"]
    assert picked.primary.name == "lab"


def test_select_unknown_resolver(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "ok.json",
        {"resolvers": [{"name": "system", "nameservers": []}]},
    )
    loaded = load_resolver_file(path)
    with pytest.raises(ResolverConfigError, match="Unknown resolver"):
        select_resolvers(loaded, ["cloudflare"])


def test_settings_from_nameservers_dedupes() -> None:
    settings = settings_from_nameservers(["192.0.2.1", "192.0.2.1"])
    assert settings.primary.name == "cli"
    assert settings.primary.nameservers == ("192.0.2.1",)
    assert settings.extras == ()
