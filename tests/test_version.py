"""Single source of truth for the release version."""

from analyzer.version import __version__


def test_version_is_semver_triplet() -> None:
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
    assert __version__ == "1.0.0"
