"""Centralized logging setup."""

from __future__ import annotations

import logging
import os
import re
import sys
import time
import traceback
import uuid
from contextlib import suppress
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from . import secure_log
from .secure_log import InsecureLogFileError

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
_file_logging_warned = False


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
    """Apply text redaction before handlers format a log record.

    The traceback is folded into the message and `exc_info` is cleared, rather
    than left for each handler to render. `RichHandler(rich_tracebacks=True)`
    renders straight from `exc_info` and never passes through
    `RedactingFormatter`, so it printed the redacted message and then the same
    secret again, raw, one line later. Emptying `exc_info` here means NO
    handler - present or future - can reach the unredacted exception.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        text = redact_log_text(record.getMessage())
        if record.exc_info:
            rendered = "".join(traceback.format_exception(*record.exc_info))
            text = f"{text}\n{redact_log_text(rendered).rstrip()}"
            record.exc_info = None
        elif record.exc_text:
            # A handler formatted this record before us and cached the raw text.
            text = f"{text}\n{redact_log_text(record.exc_text).rstrip()}"
        record.exc_text = None
        record.msg = text
        record.args = ()
        return True


class RedactingFormatter(logging.Formatter):
    """Redact already-formatted output, including exception tracebacks."""

    def format(self, record: logging.LogRecord) -> str:
        return redact_log_text(super().format(record))


def _warn_once(message: str) -> None:
    """Emit at most one sanitized file-logging warning, straight to stderr.

    Straight to stderr and not through `logging`: the thing that just failed is
    the log file, and routing the failure through the logger is how a hardening
    error would end up written into the very file it refused to secure.
    """
    global _file_logging_warned
    if _file_logging_warned:
        return
    _file_logging_warned = True
    print(f"warning: {redact_log_text(message)}", file=sys.stderr)


class OwnerOnlyRotatingFileHandler(RotatingFileHandler):
    """RotatingFileHandler that opens only files proven to be owner-only.

    The base class opens through the ambient umask, so a typical 0o022 umask
    published the log as 0o644. Every open - the primary file and the fresh
    primary after each rollover - goes through `secure_log.open_secure`, which
    raises rather than returning a descriptor on a file it could not secure.
    There is deliberately no `super()._open()` fallback: the previous version
    had one, and it followed the very symlink `O_NOFOLLOW` had just rejected.

    Rotated backups are renames of an already-0600 primary, so they inherit the
    mode; the rename *destinations* are still checked, because a symlink
    planted at `cli.log.1` would otherwise capture the next rollover.
    """

    def __init__(self, *args, **kwargs):
        self._file_logging_failed = False
        super().__init__(*args, **kwargs)

    def _open(self):
        fd = secure_log.open_secure(self.baseFilename)
        return os.fdopen(fd, self.mode, encoding=self.encoding, errors=self.errors)

    def doRollover(self):  # noqa: N802 - the base class spells it this way
        # rotation_filename, not string concatenation, so a configured namer's
        # real destinations are the ones that get checked.
        for index in range(1, self.backupCount + 1):
            secure_log.reject_if_unsafe_target(
                self.rotation_filename(f"{self.baseFilename}.{index}")
            )
        super().doRollover()

    def emit(self, record: logging.LogRecord) -> None:
        # RotatingFileHandler.emit funnels every exception into handleError, so
        # the fail-closed decision has to be made here rather than around it.
        if self._file_logging_failed:
            return
        try:
            if self.shouldRollover(record):
                self.doRollover()
            logging.FileHandler.emit(self, record)
        except InsecureLogFileError as exc:
            self._disable(exc)
        except Exception:
            # Every other failure keeps the base class's behaviour.
            self.handleError(record)

    def _disable(self, exc: InsecureLogFileError) -> None:
        """Stop writing this file for good. The console handler keeps working."""
        self._file_logging_failed = True
        with suppress(Exception):
            self.close()
        _warn_once(f"file logging disabled: {exc}")


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
        # rich is a hard install dependency, so there is no ImportError arm.
        from rich.console import Console
        from rich.logging import RichHandler

        # stderr, explicitly: a bare Console binds to sys.stdout, which the
        # --json contract reserves for structured records (and which
        # `mb ls > out.txt` sends to the user's data file).
        handler: logging.Handler = RichHandler(
            console=Console(stderr=True),
            rich_tracebacks=True,
            show_path=False,
            show_time=True,
            markup=False,
        )
        handler.setLevel(level)
        handler.addFilter(context_filter)
        handler.addFilter(redacting_filter)
        root.addHandler(handler)

    if log_file:
        # A log file that cannot be made owner-only is not written at all. The
        # CLI keeps running on the console handler rather than dying over a log
        # file, but it never degrades to an ordinary unprotected open.
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            fh = OwnerOnlyRotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
        except OSError as exc:
            _warn_once(f"file logging disabled: {exc}")
            _quiet_noisy_libraries()
            return
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

    _quiet_noisy_libraries()


def _quiet_noisy_libraries() -> None:
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
