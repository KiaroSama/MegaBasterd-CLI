"""The logger must not leak what the central sanitizer already catches.

`utils/logger.py` kept its own parallel set of secret patterns. They drifted:
Digest headers, Proxy-Authorization, Bearer tokens, and free-text
`password:` / `SID was` / `MFA code` values all reached the console AND the log
file, even though `utils/redaction.py` had learned to catch every one of them.

These tests assert on the REAL emitted artifacts - a file handler's contents and
a formatted traceback - not just on the helper's return value.
"""

from __future__ import annotations

import logging

import pytest

from megabasterd_cli.utils.logger import RedactingFormatter, redact_log_text

# Every value here is invented; none is a real credential.
LEAKS = {
    "digest-nonce": (
        'Authorization: Digest username="u", nonce="SENTINELNONCE", response="SENTINELRESP"',
        ["SENTINELNONCE", "SENTINELRESP"],
    ),
    "proxy-authorization": ("Proxy-Authorization: Basic SENTINELBASIC", ["SENTINELBASIC"]),
    "bearer": ("sent Bearer SENTINELBEARER upstream", ["SENTINELBEARER"]),
    "free-text-password": ("the password is SENTINELPW", ["SENTINELPW"]),
    "password-colon": ("password: SENTINELPW2", ["SENTINELPW2"]),
    "sid-was": ("SID was SENTINELSID", ["SENTINELSID"]),
    "session-id": ("session id: SENTINELSESSION", ["SENTINELSESSION"]),
    "mfa-code": ("MFA code 123456", ["123456"]),
    "api-key": ("api key: SENTINELAPIKEY", ["SENTINELAPIKEY"]),
    "vault-passphrase": ("vault passphrase = SENTINELVAULT", ["SENTINELVAULT"]),
    "proxy-userinfo": (
        "using http://user:SENTINELPROXYPW@proxy.example:8080",
        ["SENTINELPROXYPW"],
    ),
}


@pytest.mark.parametrize("text,secrets", LEAKS.values(), ids=list(LEAKS))
def test_redact_log_text_covers_every_central_shape(text, secrets):
    cleaned = redact_log_text(text)
    for secret in secrets:
        assert secret not in cleaned, f"{secret} leaked: {cleaned}"


@pytest.mark.parametrize("text,secrets", LEAKS.values(), ids=list(LEAKS))
def test_secrets_never_reach_the_log_file(tmp_path, text, secrets):
    """End-to-end through a real handler, not just the helper."""
    log_path = tmp_path / "cli.log"
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(RedactingFormatter("%(message)s"))
    logger = logging.getLogger(f"test.leak.{abs(hash(text))}")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.propagate = False
    logger.setLevel(logging.DEBUG)

    logger.info("%s", text)
    handler.close()

    written = log_path.read_text(encoding="utf-8")
    for secret in secrets:
        assert secret not in written, f"{secret} was written to the log file: {written}"


def test_secrets_in_an_exception_traceback_are_redacted(tmp_path):
    """`exc_info` text is formatted by the handler; it must be scrubbed too."""
    log_path = tmp_path / "cli.log"
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(RedactingFormatter("%(message)s"))
    logger = logging.getLogger("test.leak.traceback")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.propagate = False
    logger.setLevel(logging.DEBUG)

    try:
        raise RuntimeError("login rejected, password: SENTINELTRACEBACK")
    except RuntimeError:
        logger.exception("transfer failed")
    handler.close()

    written = log_path.read_text(encoding="utf-8")
    assert "SENTINELTRACEBACK" not in written, written
    assert "transfer failed" in written, "the useful message must survive"


def test_ordinary_log_lines_stay_readable():
    text = "Downloaded chunk 4 of 12 in 1.20s"
    assert redact_log_text(text) == text


def test_mega_urls_are_still_removed_entirely():
    cleaned = redact_log_text("fetching https://mega.nz/file/ABCD1234#SECRETKEYVALUE now")
    assert "SECRETKEYVALUE" not in cleaned
    assert "<redacted-url>" in cleaned


def test_emails_are_still_masked():
    assert "user@example.com" not in redact_log_text("logged in as user@example.com")


def test_redaction_is_idempotent():
    once = redact_log_text("password: SENTINELPW and SID was SENTINELSID")
    assert redact_log_text(once) == once
