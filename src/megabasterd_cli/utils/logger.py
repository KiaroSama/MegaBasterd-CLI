"""Centralized logging setup."""

from __future__ import annotations

import logging
import re
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

_URL_RE = re.compile(r"https?://[^\s'\"\]\)>,]+", re.IGNORECASE)
_MEGA_API_PATH_RE = re.compile(r"/cs\?[^\s'\"\]\)>,]+", re.IGNORECASE)
_SENSITIVE_FIELD_RE = re.compile(
    r"((?:'|\")"
    r"(?:k|at|g|fa|uh|mfa|sid|key|attr|api_key|apikey|APIKEY|privk|csid|tsid)"
    r"(?:'|\")\s*:\s*)(?:'|\")[^'\"]+(?:'|\")"
)


def redact_log_text(text: str) -> str:
    """Remove MEGA URLs and token-like payload values from debug logs."""

    def redact_url(match: re.Match[str]) -> str:
        url = match.group(0)
        lowered = url.lower()
        if "mega.nz" in lowered or "mega.co.nz" in lowered or "userstorage.mega" in lowered:
            return "<redacted-url>"
        return url

    redacted = _URL_RE.sub(redact_url, text)
    redacted = _MEGA_API_PATH_RE.sub("/cs?<redacted-query>", redacted)
    return _SENSITIVE_FIELD_RE.sub(r"\1'<redacted>'", redacted)


class RedactingFilter(logging.Filter):
    """Apply text redaction before handlers format a log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_log_text(record.getMessage())
        record.args = ()
        return True


class RedactingFormatter(logging.Formatter):
    """Redact already-formatted output, including exception tracebacks."""

    def format(self, record: logging.LogRecord) -> str:
        return redact_log_text(super().format(record))


def setup_logging(
    level: str | int = "WARNING",
    log_file: Path | None = None,
    quiet: bool = False,
    max_bytes: int = 5_000_000,
    backup_count: int = 5,
) -> None:
    """Configure root logger for the CLI.

    Console output is colorized when stdout is a TTY. Optional file logging
    writes plain text without colors.
    """
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.DEBUG)
    root.filters.clear()
    root.addFilter(RedactingFilter())
    logging.captureWarnings(True)

    if not quiet:
        try:
            from rich.logging import RichHandler

            handler = RichHandler(
                rich_tracebacks=True,
                show_path=False,
                show_time=True,
                markup=False,
                level=level if isinstance(level, str) else logging.getLevelName(level),
            )
            handler.setLevel(level)
            root.addHandler(handler)
        except ImportError:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(
                RedactingFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            )
            handler.setLevel(level)
            root.addHandler(handler)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(
            RedactingFormatter(
                "%(asctime)s.%(msecs)03d [%(levelname)s] "
                "pid=%(process)d thread=%(threadName)s "
                "%(name)s:%(funcName)s:%(lineno)d - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        root.addHandler(fh)
        root.debug("File logging initialized at %s", log_file)

    # Quiet noisy libraries by default
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
