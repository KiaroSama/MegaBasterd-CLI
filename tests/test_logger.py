"""Logging redaction tests."""

from megabasterd_cli.utils.logger import redact_log_text


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
