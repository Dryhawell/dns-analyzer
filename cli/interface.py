"""CLI interface.

Phase 14 will add argparse (--record, --security, --all, --reverse, ...).
Phase 1 only confirms the project skeleton runs.
"""

import sys


def _ensure_utf8_stdout() -> None:
    """Windows consoles often default to a legacy code page."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")


def run() -> None:
    _ensure_utf8_stdout()
    print("DNS Analyzer — Phase 1 iskeleti hazır")
