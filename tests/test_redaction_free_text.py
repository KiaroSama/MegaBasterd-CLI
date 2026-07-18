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


# ---------------------------------------------------------------------------
# Complete authentication-header handling.
#
# A header value used to be cut at the first whitespace-delimited token, so a
# Digest header leaked nonce, response, cnonce and opaque.
# ---------------------------------------------------------------------------

DIGEST_HEADER = (
    'Authorization: Digest username="alice", realm="mega", '
    'nonce="dcd98b7102dd2f0e10a3", uri="/api", '
    'response="6629fae49393a05397450978507c4ef1", '
    'opaque="5ccc069c403ebaf9f0171e9517f40e41", qop=auth, '
    'nc=00000001, cnonce="0a4f113b8fa5"'
)
DIGEST_SECRETS = [
    "dcd98b7102dd2f0e10a3",
    "6629fae49393a05397450978507c4ef1",
    "5ccc069c403ebaf9f0171e9517f40e41",
    "0a4f113b8fa5",
]


def test_full_digest_header_leaks_nothing():
    cleaned = redact_text(DIGEST_HEADER)
    for secret in DIGEST_SECRETS:
        assert secret not in cleaned, f"{secret} leaked: {cleaned}"
    assert cleaned.startswith("Authorization:")


def test_bare_digest_challenge_is_redacted():
    text = 'Digest username="alice", response="6629fae49393a05397450978507c4ef1"'
    cleaned = redact_text(text)
    assert "6629fae49393a05397450978507c4ef1" not in cleaned
    assert "alice" not in cleaned


def test_digest_word_in_prose_is_left_alone():
    assert redact_text("Digest authentication failed") == "Digest authentication failed"


@pytest.mark.parametrize(
    "header",
    [
        "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==",
        "proxy-authorization: Bearer proxy-fake-token",
        'Proxy-Authorization: Digest username="bob", response="deadbeefcafe"',
        "PROXY-AUTHORIZATION=Basic dXNlcjpwYXNzd29yZA==",
    ],
)
def test_proxy_authorization_variants_are_redacted(header):
    cleaned = redact_text(header)
    for leak in ("dXNlcjpwYXNzd29yZA==", "proxy-fake-token", "deadbeefcafe", "bob"):
        assert leak not in cleaned


def test_multiline_text_redacts_only_the_header_line():
    text = (
        "POST /api HTTP/1.1\n"
        'Authorization: Digest username="alice", response="deadbeefcafe"\n'
        "Content-Type: application/json\n"
        "the transfer then failed for an unrelated reason"
    )
    cleaned = redact_text(text)
    assert "deadbeefcafe" not in cleaned
    assert "Content-Type: application/json" in cleaned, "unrelated lines must survive"
    assert "the transfer then failed for an unrelated reason" in cleaned
    assert len(cleaned.splitlines()) == 4


def test_multiple_secrets_in_one_string_are_all_redacted():
    text = "password: p1-fake and sid: s2-fake and token: t3-fake"
    cleaned = redact_text(text)
    for leak in ("p1-fake", "s2-fake", "t3-fake"):
        assert leak not in cleaned
    assert cleaned.count(REDACTED) == 3


def test_secret_adjacent_to_punctuation_keeps_the_sentence_intact():
    cleaned = redact_text("failed (password: hunter2-fake), retrying now")
    assert "hunter2-fake" not in cleaned
    assert cleaned == f"failed (password: {REDACTED}), retrying now"


def test_trailing_sentence_punctuation_is_preserved():
    assert redact_text("the sid was abc123fake.") == f"the sid was {REDACTED}."


def test_header_redaction_is_idempotent():
    once = redact_text(DIGEST_HEADER)
    assert redact_text(once) == once


def test_redaction_has_no_catastrophic_backtracking():
    """A pathological input must complete promptly, not hang the CLI."""
    import time

    hostile = "Authorization: " + ("a" * 20000) + " " + ("b=c, " * 4000)
    started = time.monotonic()
    redact_text(hostile)
    assert time.monotonic() - started < 2.0


def test_machine_json_records_are_sanitized_end_to_end(tmp_path, capsys):
    """The central sanitizer must be applied by MachineOutput itself, not by
    each caller remembering to scrub."""
    import io
    import json as _json

    from megabasterd_cli.ui.machine_output import MachineOutput

    out = MachineOutput(enabled=True)
    out._stream = io.StringIO()
    out.emit(
        event="result",
        status="failed",
        error=DIGEST_HEADER,
        detail={"cause": ["password: nested-fake"]},
    )
    line = out._stream.getvalue()
    record = _json.loads(line)
    for secret in DIGEST_SECRETS + ["nested-fake"]:
        assert secret not in line
    assert record["status"] == "failed"


def test_cli_error_text_is_sanitized(tmp_path, monkeypatch):
    """A secret inside an exception message must not reach stderr verbatim."""
    from click.testing import CliRunner

    from megabasterd_cli.cli import cli

    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "User"))
    monkeypatch.setenv("MEGABASTERD_PROJECT_ROOT", str(tmp_path))
    runner = CliRunner()  # streams mixed: assert over everything the user sees
    result = runner.invoke(cli, ["download", "https://mega.nz/file/ABCD1234#SUPERSECRETKEYVALUE"])
    assert "SUPERSECRETKEYVALUE" not in result.output
