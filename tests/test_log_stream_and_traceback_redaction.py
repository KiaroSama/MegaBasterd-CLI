"""Three ways a secret or a diagnostic reached the wrong stream.

1. The Rich console handler bound to `sys.stdout`, so every log line landed in
   the channel `--json` reserves for structured records - and in the file when
   a user redirected `mb ls > out.txt`. The ImportError fallback three lines
   below always used stderr; only the Rich branch drifted.
2. `RedactingFilter` rewrote `record.msg` but left `record.exc_info` alone, and
   `RichHandler(rich_tracebacks=True)` renders the exception straight from
   `exc_info` without ever touching `RedactingFormatter`. The redacted message
   printed, then the same secret printed raw one line later.
3. `display_value` special-cased exactly two keys, so `config show` printed
   `smart_proxy_url` with its `user:pass@` intact - the same value `proxy list`
   redacts one command over.
"""

from __future__ import annotations

import io
import logging
from contextlib import redirect_stderr, redirect_stdout

import pytest

from megabasterd_cli import config as cfg
from megabasterd_cli.utils import logger as lg

SECRET_URL = "http://alice:hunter2@1.2.3.4:8080"


@pytest.fixture()
def clean_root():
    """setup_logging mutates the root logger; put it back afterwards."""
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_filters = list(root.filters)
    saved_level = root.level
    yield root
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.handlers.extend(saved_handlers)
    root.filters.clear()
    root.filters.extend(saved_filters)
    root.setLevel(saved_level)


# ---------------------------------------------------------------------------
# L1: diagnostics belong on stderr
# ---------------------------------------------------------------------------


def test_console_logging_never_touches_stdout(clean_root):
    pytest.importorskip("rich")
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        lg.setup_logging(level="WARNING")
        logging.getLogger("megabasterd_cli.test").warning("MARKERWORD")
        for handler in logging.getLogger().handlers:
            handler.flush()

    assert "MARKERWORD" not in out.getvalue()
    assert "MARKERWORD" in err.getvalue()


def test_rich_handler_is_actually_the_one_installed(clean_root):
    """Guard the test above: if Rich is missing it would pass for free."""
    from rich.logging import RichHandler

    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(io.StringIO()):
        lg.setup_logging(level="WARNING")
    assert any(isinstance(h, RichHandler) for h in logging.getLogger().handlers)


# ---------------------------------------------------------------------------
# L2: the traceback must not escape redaction
# ---------------------------------------------------------------------------


def _record_with_exception() -> logging.LogRecord:
    try:
        raise RuntimeError(f"proxy auth failed for {SECRET_URL} (password: swordfish)")
    except RuntimeError:
        import sys

        return logging.LogRecord(
            name="megabasterd_cli.test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="Fatal error: %s",
            args=("boom",),
            exc_info=sys.exc_info(),
        )


def test_filter_neutralizes_exc_info_so_no_handler_can_render_it_raw():
    record = _record_with_exception()
    assert lg.RedactingFilter().filter(record) is True

    assert record.exc_info is None, "a handler could still render the raw traceback"
    assert "hunter2" not in record.msg
    assert "swordfish" not in record.msg


def test_redacted_traceback_is_still_present_not_merely_dropped():
    record = _record_with_exception()
    lg.RedactingFilter().filter(record)

    assert "Traceback" in record.msg
    assert "RuntimeError" in record.msg
    assert "proxy auth failed" in record.msg


def test_file_handler_output_carries_the_redacted_traceback(clean_root, tmp_path):
    log_file = tmp_path / "cli.log"
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        lg.setup_logging(level="WARNING", log_file=log_file, quiet=True)
        try:
            raise RuntimeError(f"proxy auth failed for {SECRET_URL} (password: swordfish)")
        except RuntimeError:
            logging.getLogger("megabasterd_cli.test").exception("Fatal error")
        for handler in logging.getLogger().handlers:
            handler.flush()

    written = log_file.read_text(encoding="utf-8")
    assert "RuntimeError" in written
    assert "hunter2" not in written
    assert "swordfish" not in written


# ---------------------------------------------------------------------------
# L4: `config show` / `config get` must agree with `proxy list`
# ---------------------------------------------------------------------------


def test_display_value_redacts_credentials_in_any_string_field():
    shown = cfg.display_value("smart_proxy_url", SECRET_URL)
    assert "hunter2" not in shown
    assert "1.2.3.4:8080" in shown


def test_display_value_redacts_auth_headers_in_run_command():
    shown = cfg.display_value("run_command", 'curl -H "Authorization: Bearer sk-abc123"')
    assert "sk-abc123" not in shown


def test_display_value_keeps_its_existing_special_cases():
    from megabasterd_cli.utils.redaction import REDACTED

    assert cfg.display_value("connect_proxy_password", "swordfish") == REDACTED
    assert cfg.display_value("elc_accounts", {"h": {"password": "swordfish"}}) == {
        "h": {"password": REDACTED}
    }
    assert cfg.display_value("smart_proxy_url", None) is None
    assert cfg.display_value("max_threads", 4) == 4
