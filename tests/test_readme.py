"""README contract for Phase 21. No network access."""

from pathlib import Path

_README = Path(__file__).resolve().parents[1] / "README.md"

_REQUIRED_HEADINGS = (
    "# DNS Analyzer",
    "## Overview",
    "## Features",
    "## Why DNS Security Matters",
    "## DNS Record Types",
    "## Installation",
    "## Usage",
    "## CLI Examples",
    "## Security Analysis",
    "## DNSSEC",
    "## SPF / DKIM / DMARC",
    "## CAA",
    "## Reverse DNS",
    "## Architecture",
    "## Testing",
    "## Limitations",
    "## Responsible Use",
    "## Roadmap",
    "## License",
)


def test_readme_has_required_sections() -> None:
    text = _README.read_text(encoding="utf-8")
    missing = [heading for heading in _REQUIRED_HEADINGS if heading not in text]
    assert missing == []


def test_readme_says_not_a_vulnerability_scanner() -> None:
    text = _README.read_text(encoding="utf-8").lower()
    assert "not a vulnerability scanner" in text
    assert "compromised" in text
