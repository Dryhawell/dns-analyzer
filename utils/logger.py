"""Application logging setup.

Logs go to logs/dns-analyzer.log by default. They are diagnostics, not the
user-facing CLI, and they must never carry secrets or raw DNS payloads
(TXT tokens, full rdata, packet dumps).
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOGGER_NAME = "dns_analyzer"
DEFAULT_LOG_PATH = Path("logs") / "dns-analyzer.log"
_FILE_HANDLER_NAME = "dns_analyzer_file"

_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def get_logger(suffix: str = "") -> logging.Logger:
    """Return dns_analyzer or a child such as dns_analyzer.resolver."""
    if not suffix:
        return logging.getLogger(LOGGER_NAME)
    return logging.getLogger(f"{LOGGER_NAME}.{suffix}")


def configure_logging(log_path: Path | str | None = None) -> Path:
    """Attach a rotating file handler. Safe to call more than once.

    Does not log to stdout/stderr: JSON export and the human CLI stay clean.
    """
    path = Path(log_path) if log_path is not None else DEFAULT_LOG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    for handler in list(logger.handlers):
        if isinstance(handler, logging.NullHandler):
            logger.removeHandler(handler)

    if any(getattr(handler, "name", "") == _FILE_HANDLER_NAME for handler in logger.handlers):
        return path

    handler = RotatingFileHandler(
        path,
        maxBytes=1_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter(_FORMAT))
    handler.name = _FILE_HANDLER_NAME
    logger.addHandler(handler)
    return path


def reset_logging() -> None:
    """Remove handlers (tests). Leaves a NullHandler so unused loggers stay quiet."""
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)
    logger.addHandler(logging.NullHandler())
    logger.propagate = False


logging.getLogger(LOGGER_NAME).addHandler(logging.NullHandler())
