"""Free-text secret redaction.

Structured field-name redaction stays the primary defense; these cover the
shapes that reach output through `str(exc)` — where the secret is a substring
of a sentence, not a named field.

No real credential is used here: every fixture value is invented.
"""

from __future__ import annotations

import pytest

from megabasterd_cli.utils.redaction import REDACTED, redact_text, sanitize

REDACTED_CASES = [
    ("password: hunter2-fake", "hunter2-fake"),
    ("Password = hunter2-fake", "hunter2-fake"),
    ("the password is hunter2-fake", "hunter2-fake"),
    ('password: "quoted fake value"', "quoted fake value"),
    ("password: 'single fake value'", "single fake value"),
    ("PASSPHRASE: vault-fake-phrase", "vault-fake-phrase"),
    ("vault passphrase = vault-fake-phrase", "vault-fake-phrase"),
    ("SID was abc123fakesid", "abc123fakesid"),
    ("sid: abc123fakesid", "abc123fakesid"),
    ("session id is abc123fakesid", "abc123fakesid"),
    ("MFA code 123456", "123456"),
    ("mfa_code: 123456", "123456"),
    ("OTP 987654", "987654"),
    ("2FA code 445566", "445566"),
    ("API key: fake-api-key-value", "fake-api-key-value"),
    ("api_key=fake-api-key-value", "fake-api-key-value"),
    ("Api Key is fake-api-key-value", "fake-api-key-value"),
    ("token is fake-token-value", "fake-token-value"),
    ("access_token=fake-token-value", "fake-token-value"),
    ("Authorization: Bearer fake.jwt.value", "fake.jwt.value"),
    ("authorization=fake-header-value", "fake-header-value"),
    ("sent Bearer fake.jwt.value upstream", "fake.jwt.value"),
    ("proxy http://user:fakepass@proxy.example:8080 failed", "fakepass"),
    ("socks5://someone:fakepass@10.0.0.1:1080", "fakepass"),
    ("secret: fake-secret-value", "fake-secret-value"),
]


@pytest.mark.parametrize("text,secret", REDACTED_CASES, ids=[c[0] for c in REDACTED_CASES])
def test_free_text_secrets_are_redacted(text, secret):
    cleaned = redact_text(text)
    assert secret not in cleaned, f"{text!r} leaked through as {cleaned!r}"
    assert REDACTED in cleaned or "#<key>" in cleaned


UNCHANGED = [
    "Uploaded quarterly-report.pdf successfully",
    "Could not open C:\\Users\\me\\secret_plans.txt",
    "Basic authentication failed for the proxy",
    "password required but not provided",
    "Retrying chunk 4 of 12 after a timeout",
    "Destination /srv/backups/2026 already exists",
]


@pytest.mark.parametrize("text", UNCHANGED)
def test_ordinary_text_is_left_alone(text):
    assert redact_text(text) == text


def test_share_link_field_keeps_its_public_key():
    link = "https://mega.nz/folder/ABCD1234#PUBLICKEYVALUE"
    record = sanitize({"event": "result", "share_link": link})
    assert record["share_link"] == link


def test_share_link_still_loses_secret_query_params():
    link = "https://mega.nz/folder/ABCD1234?sid=fakesid#PUBLICKEYVALUE"
    record = sanitize({"share_link": link})
    assert "fakesid" not in record["share_link"]
    assert "#PUBLICKEYVALUE" in record["share_link"]


def test_nested_exception_records_are_scrubbed_recursively():
    record = {
        "event": "result",
        "status": "failed",
        "error": "login rejected: password: fake-nested-value",
        "details": {
            "cause": ["SID was fake-nested-sid", {"note": "api key: fake-nested-key"}],
        },
    }
    cleaned = sanitize(record)
    blob = repr(cleaned)
    for leaked in ("fake-nested-value", "fake-nested-sid", "fake-nested-key"):
        assert leaked not in blob


def test_secret_named_fields_still_win_wholesale():
    assert sanitize({"password": "anything"})["password"] == REDACTED
    assert sanitize({"api_key": "anything"})["api_key"] == REDACTED


def test_redaction_is_idempotent():
    once = redact_text("password: fake-value and sid: fake-sid")
    assert redact_text(once) == once
