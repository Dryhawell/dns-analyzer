"""Shared mailbox local-part hashing for SMIMEA and OPENPGPKEY.

RFC 7929 (OPENPGPKEY) and RFC 8162 (SMIMEA) both build the leftmost
DNS label from the leftmost 28 octets of SHA-256 of the prepared
local-part, encoded as lowercase hex. This module is that hash only.

Local-parts are never guessed. Callers pass the mailbox local-part
(the part before @).
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Sequence

HASH_OCTETS = 28
MAX_LOCALPARTS = 8
_MAX_LOCALPART_OCTETS = 64

_COMMENT = re.compile(r"\([^)]*\)")


class LocalpartError(ValueError):
    """Raised when a caller-supplied local-part cannot be prepared."""


def prepare_localpart(raw: str, *, label: str = "local-part") -> str:
    """Prepare one caller-supplied local-part. Never invent a mailbox.

    Shared by RFC 7929 and RFC 8162: if an email address is passed,
    only the local-part is kept; ASCII letters are lowercased; non-ASCII
    is NFC-normalized; the result is UTF-8 before hashing.
    """
    if not isinstance(raw, str):
        raise LocalpartError(f"{label} must be a string.")
    value = raw.strip()
    if "@" in value:
        value = value.split("@", 1)[0].strip()
    if not value:
        raise LocalpartError(
            f"{label} cannot be empty. Pass the part before @, "
            "for example alice, not a guessed mailbox list."
        )
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    value = _COMMENT.sub("", value)
    value = re.sub(r"\s*\.\s*", ".", value)
    value = value.replace("\\", "")
    value = value.strip()
    if any(ord(char) > 127 for char in value):
        value = unicodedata.normalize("NFC", value)
    value = "".join(char.lower() if char.isascii() else char for char in value)
    if not value:
        raise LocalpartError(f"{label} cannot be empty after local-part preparation.")
    encoded = value.encode("utf-8")
    if len(encoded) > _MAX_LOCALPART_OCTETS:
        raise LocalpartError(f"{label} is too long.")
    if any(ord(char) < 32 for char in value):
        raise LocalpartError(
            f"Invalid {label} {raw!r}. Pass a mailbox local-part "
            "(the part before @). Local-parts are never guessed."
        )
    return value


def hash_localpart(prepared: str) -> str:
    """Leftmost 28 octets of SHA-256(prepared local-part), lowercase hex."""
    digest = hashlib.sha256(prepared.encode("utf-8")).digest()
    return digest[:HASH_OCTETS].hex()


def localpart_hash(local_part: str, *, label: str = "local-part") -> str:
    """Prepare, then hash. Same digest for SMIMEA (RFC 8162) and OPENPGPKEY (RFC 7929)."""
    return hash_localpart(prepare_localpart(local_part, label=label))


def normalize_localparts(
    raw: Sequence[str],
    *,
    label: str,
    flag: str,
) -> tuple[str, ...]:
    """Deduplicate local-parts, keep order, cap how many we query."""
    seen: list[str] = []
    for item in raw:
        local_part = prepare_localpart(item, label=label)
        if local_part not in seen:
            seen.append(local_part)
    if len(seen) > MAX_LOCALPARTS:
        raise LocalpartError(
            f"Too many {flag} local-parts (max {MAX_LOCALPARTS}). "
            "This tool does not brute-force or guess mailbox names."
        )
    return tuple(seen)
