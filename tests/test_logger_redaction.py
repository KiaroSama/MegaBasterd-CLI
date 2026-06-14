"""Regression tests for sensitive identifier redaction in logs (Priority 8)."""

import logging

from megabasterd_cli.utils.logger import redact_log_text, setup_logging


def test_email_redacted_in_text() -> None:
    out = redact_log_text("Login failed for user alice.smith@example.com today")
    assert "alice.smith@example.com" not in out
    assert "<redacted-email>" in out


def test_user_field_redacted() -> None:
    out = redact_log_text("MEGA API request: [{'a': 'us', 'user': 'me@example.org', 'uh': 'h'}]")
    assert "me@example.org" not in out


def test_non_sensitive_text_preserved() -> None:
    out = redact_log_text("Downloaded chunk 5 of 12 (speed=10MB/s)")
    assert out == "Downloaded chunk 5 of 12 (speed=10MB/s)"


def test_child_logger_file_handler_redacts_email(tmp_path) -> None:
    log_path = tmp_path / "cli.log"
    setup_logging(level="DEBUG", log_file=log_path, quiet=True, run_id="r", command="account")
    logging.getLogger("megabasterd_cli.accounts.manager").info(
        "Refreshing account bob@example.net"
    )
    logging.shutdown()
    text = log_path.read_text(encoding="utf-8")
    assert "bob@example.net" not in text
    assert "<redacted-email>" in text


def test_exception_traceback_redacts_email(tmp_path) -> None:
    log_path = tmp_path / "exc.log"
    setup_logging(level="DEBUG", log_file=log_path, quiet=True, run_id="r", command="account")
    try:
        raise ValueError("bad login for carol@example.com")
    except ValueError:
        logging.getLogger("megabasterd_cli.core.client").exception("login error")
    logging.shutdown()
    text = log_path.read_text(encoding="utf-8")
    assert "carol@example.com" not in text
