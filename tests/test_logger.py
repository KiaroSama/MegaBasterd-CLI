"""Logging redaction tests."""

import logging

from megabasterd_cli.utils.logger import redact_log_text, setup_logging


def test_redact_log_text_hides_mega_urls_and_sensitive_fields():
    text = (
        "MEGA API response: [{'g': 'http://gfs204n301.userstorage.mega.co.nz/dl/token', "
        "'k': 'folder:file-key', 'fa': 'thumbnail-token', 'a': 'f'}] "
        "https://mega.nz/folder/abc#secret /cs?id=1&ak=key&n=folder"
    )

    redacted = redact_log_text(text)

    assert "userstorage.mega" not in redacted
    assert "https://mega.nz" not in redacted
    assert "n=folder" not in redacted
    assert "folder:file-key" not in redacted
    assert "thumbnail-token" not in redacted
    assert "'a': 'f'" in redacted
    assert "<redacted-url>" in redacted


def test_redact_log_text_hides_sensitive_query_values():
    text = "GET https://example.invalid/api?token=secret&safe=value&password=pw"

    redacted = redact_log_text(text)

    assert "secret" not in redacted
    assert "password=pw" not in redacted
    assert "safe=value" in redacted
    assert "token=%3Credacted%3E" in redacted


def test_setup_logging_writes_contextual_file_records(tmp_path):
    log_path = tmp_path / "cli.log"

    setup_logging(
        level="DEBUG",
        log_file=log_path,
        quiet=True,
        run_id="testrun",
        command="download",
    )
    logging.getLogger("megabasterd_cli.test").info(
        "Downloaded from https://mega.nz/file/abc#secret"
    )
    logging.shutdown()

    text = log_path.read_text(encoding="utf-8")
    assert "run=testrun" in text
    assert "cmd=download" in text
    assert "megabasterd_cli.test" in text
    assert "https://mega.nz" not in text
    assert "<redacted-url>" in text
