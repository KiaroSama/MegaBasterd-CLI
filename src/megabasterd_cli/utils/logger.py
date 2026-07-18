"""Centralized logging setup."""

from __future__ import annotations

import logging
import os
import re
import sys
import time
import uuid
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_URL_RE = re.compile(r"https?://[^\s'\"\]\)>,]+", re.IGNORECASE)
_MEGA_API_PATH_RE = re.compile(r"/cs\?[^\s'\"\]\)>,]+", re.IGNORECASE)
# Email / account identifiers: redacted to avoid leaking who is logged in.
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_SENSITIVE_QUERY_KEYS = {
    "ak",
    "api_key",
    "apikey",
    "auth",
    "at",
    "email",
    "fa",
    "g",
    "k",
    "key",
    "mfa",
    "n",
    "password",
    "sid",
    "session",
    "token",
    "uh",
    "user",
}
_SENSITIVE_FIELD_RE = re.compile(
    r"((?:'|\")"
    r"(?:k|at|g|fa|uh|mfa|sid|key|attr|api_key|apikey|APIKEY|password|"
    r"passphrase|token|cookie|session|privk|csid|tsid|user|email)"
    r"(?:'|\")\s*:\s*)(?:'|\")[^'\"]+(?:'|\")"
)
_context = {"run_id": "-", "command": "-"}
_process_started_at = time.perf_counter()
_shutdown_log_registered = False


def _redact_url_query(url: str) -> str:
    """Redact sensitive query keys in non-MEGA URLs that may still appear in logs."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.query:
        return url
    query = []
    changed = False
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in _SENSITIVE_QUERY_KEYS:
            query.append((key, "<redacted>"))
            changed = True
        else:
            query.append((key, value))
    if not changed:
        return url
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def redact_log_text(text: str) -> str:
    """Remove secrets, MEGA URLs, and account identifiers from log output.

    This composes TWO layers rather than maintaining a second, parallel set of
    patterns. The log-specific rules below (whole-URL removal, `/cs?` query
    stripping, e-mail masking) have no equivalent in the shared sanitizer, but
    everything a secret can look like in free text is delegated to it.

    Keeping a private copy of the secret patterns here is exactly how this
    drifted: the logger leaked Digest headers, Proxy-Authorization, Bearer
    tokens, and free-text `password:` / `SID was` / `MFA code` values that the
    central sanitizer had already learned to catch.
    """
    from .redaction import redact_text

    def redact_url(match: re.Match[str]) -> str:
        url = match.group(0)
        lowered = url.lower()
        if "mega.nz" in lowered or "mega.co.nz" in lowered or "userstorage.mega" in lowered:
            return "<redacted-url>"
        return _redact_url_query(url)

    # Central sanitizer FIRST: it works on the raw text, before URLs are
    # replaced by placeholders that would hide an embedded credential.
    redacted = redact_text(text)
    redacted = _URL_RE.sub(redact_url, redacted)
    redacted = _MEGA_API_PATH_RE.sub("/cs?<redacted-query>", redacted)
    redacted = _SENSITIVE_FIELD_RE.sub(r"\1'<redacted>'", redacted)
    return _EMAIL_RE.sub("<redacted-email>", redacted)


def set_log_context(run_id: str | None = None, command: str | None = None) -> None:
    """Set fields injected into every log record."""
    if run_id:
        _context["run_id"] = run_id
    if command:
        _context["command"] = command


class ContextFilter(logging.Filter):
    """Attach stable run context to every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.run_id = _context["run_id"]
        record.command = _context["command"]
        return True


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


def _register_shutdown_log() -> None:
    global _shutdown_log_registered
    if _shutdown_log_registered:
        return
    _shutdown_log_registered = True

    import atexit

    def _log_shutdown() -> None:
        elapsed = time.perf_counter() - _process_started_at
        logging.getLogger("megabasterd_cli.lifecycle").info(
            "CLI process shutdown elapsed_seconds=%.3f", elapsed
        )

    atexit.register(_log_shutdown)


def setup_logging(
    level: str | int = "WARNING",
    log_file: Path | None = None,
    quiet: bool = False,
    max_bytes: int = 5_000_000,
    backup_count: int = 5,
    run_id: str | None = None,
    command: str | None = None,
) -> None:
    """Configure root logger for the CLI.

    Console output is colorized when stdout is a TTY. Optional file logging
    writes plain text without colors.
    """
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
        existing.close()
    root.setLevel(logging.DEBUG)
    root.filters.clear()
    set_log_context(
        run_id or os.environ.get("MEGABASTERD_RUN_ID") or uuid.uuid4().hex[:12], command or "-"
    )
    context_filter = ContextFilter()
    redacting_filter = RedactingFilter()
    root.addFilter(context_filter)
    root.addFilter(redacting_filter)
    logging.captureWarnings(True)
    _register_shutdown_log()

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
            handler.addFilter(context_filter)
            handler.addFilter(redacting_filter)
            root.addHandler(handler)
        except ImportError:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(
                RedactingFormatter(
                    "%(asctime)s [%(levelname)s] run=%(run_id)s cmd=%(command)s "
                    "%(name)s: %(message)s"
                )
            )
            handler.setLevel(level)
            handler.addFilter(context_filter)
            handler.addFilter(redacting_filter)
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
        fh.addFilter(context_filter)
        fh.addFilter(redacting_filter)
        fh.setFormatter(
            RedactingFormatter(
                "%(asctime)s.%(msecs)03d [%(levelname)s] "
                "run=%(run_id)s cmd=%(command)s pid=%(process)d thread=%(threadName)s "
                "%(name)s:%(funcName)s:%(lineno)d - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        root.addHandler(fh)
        root.debug("File logging initialized at %s", log_file)

    # Quiet noisy libraries by default
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
