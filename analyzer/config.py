"""Load named recursive resolvers from a JSON config file.

Public resolver IPs are not compiled into the program. The example file is a
template; operators fill in resolvers they are allowed to query.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from analyzer.exceptions import InvalidIPError, ResolverConfigError
from analyzer.reverse import parse_ip

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
_MAX_RESOLVERS = 8
_MAX_NAMESERVERS = 4
_MAX_DELAY = 10.0


@dataclass(frozen=True)
class ResolverProfile:
    """One recursive resolver. Empty nameservers means the OS list."""

    name: str
    nameservers: tuple[str, ...]


@dataclass(frozen=True)
class ResolverSettings:
    profiles: tuple[ResolverProfile, ...]
    delay_seconds: float = 0.0

    @property
    def primary(self) -> ResolverProfile:
        return self.profiles[0]

    @property
    def extras(self) -> tuple[ResolverProfile, ...]:
        return self.profiles[1:]


def os_default_settings() -> ResolverSettings:
    return ResolverSettings(profiles=(ResolverProfile("system", ()),))


def settings_from_nameservers(ips: Sequence[str]) -> ResolverSettings:
    """CLI --nameserver list: one profile, OS resolver is not used."""
    servers = _parse_nameservers(ips, label="--nameserver")
    if not servers:
        raise ResolverConfigError("Provide at least one --nameserver IP.")
    return ResolverSettings(profiles=(ResolverProfile("cli", servers),))


def load_resolver_file(path: Path) -> ResolverSettings:
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ResolverConfigError(f"Could not read config file: {exc}") from exc
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ResolverConfigError(f"Config is not valid JSON: {exc.msg}.") from exc
    if not isinstance(payload, dict):
        raise ResolverConfigError("Config root must be a JSON object.")
    delay = _parse_delay(payload.get("delay_seconds", 0))
    entries = payload.get("resolvers")
    if not isinstance(entries, list) or not entries:
        raise ResolverConfigError("Config must include a non-empty 'resolvers' list.")
    if len(entries) > _MAX_RESOLVERS:
        raise ResolverConfigError(f"At most {_MAX_RESOLVERS} resolvers are allowed.")
    profiles: list[ResolverProfile] = []
    seen: set[str] = set()
    for index, item in enumerate(entries):
        profile = _parse_profile(item, index)
        if profile.name in seen:
            raise ResolverConfigError(f"Duplicate resolver name {profile.name!r}.")
        seen.add(profile.name)
        profiles.append(profile)
    return ResolverSettings(profiles=tuple(profiles), delay_seconds=delay)


def select_resolvers(
    settings: ResolverSettings,
    names: Sequence[str] | None,
) -> ResolverSettings:
    """Keep config order, or the order of --resolver flags."""
    if not names:
        return settings
    by_name = {profile.name: profile for profile in settings.profiles}
    selected: list[ResolverProfile] = []
    seen: set[str] = set()
    for raw in names:
        name = raw.strip()
        if name in seen:
            continue
        if name not in by_name:
            known = ", ".join(profile.name for profile in settings.profiles)
            raise ResolverConfigError(
                f"Unknown resolver {name!r}. Names in this file: {known}."
            )
        selected.append(by_name[name])
        seen.add(name)
    if not selected:
        raise ResolverConfigError("No resolvers selected.")
    return ResolverSettings(profiles=tuple(selected), delay_seconds=settings.delay_seconds)


def nameserver_arg(profile: ResolverProfile) -> list[str] | None:
    """None → dnspython uses the operating system resolver list."""
    return list(profile.nameservers) or None


def _parse_delay(value: object) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ResolverConfigError("delay_seconds must be a number.")
    delay = float(value)
    if delay < 0:
        raise ResolverConfigError("delay_seconds cannot be negative.")
    if delay > _MAX_DELAY:
        raise ResolverConfigError(f"delay_seconds cannot exceed {_MAX_DELAY:.0f}.")
    return delay


def _parse_profile(item: object, index: int) -> ResolverProfile:
    if not isinstance(item, dict):
        raise ResolverConfigError(f"Resolver entry {index} must be an object.")
    name = item.get("name")
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name.strip()):
        raise ResolverConfigError(
            f"Resolver entry {index} needs a name like 'system' or 'office-dns'."
        )
    servers = item.get("nameservers", [])
    if servers is None:
        servers = []
    if not isinstance(servers, list):
        raise ResolverConfigError(f"Resolver {name!r}: nameservers must be a list.")
    parsed = _parse_nameservers(servers, label=f"resolver {name!r}")
    return ResolverProfile(name=name.strip(), nameservers=parsed)


def _parse_nameservers(values: Sequence[object], *, label: str) -> tuple[str, ...]:
    if len(values) > _MAX_NAMESERVERS:
        raise ResolverConfigError(f"{label}: at most {_MAX_NAMESERVERS} nameserver IPs.")
    servers: list[str] = []
    seen: set[str] = set()
    for raw in values:
        if not isinstance(raw, str):
            raise ResolverConfigError(f"{label}: nameserver entries must be strings.")
        try:
            text = str(parse_ip(raw))
        except InvalidIPError as exc:
            raise ResolverConfigError(f"{label}: {exc}") from exc
        if text in seen:
            continue
        seen.add(text)
        servers.append(text)
    return tuple(servers)
