"""Regression tests for startup-args redaction in CLI logs.

Reproduces a defect found during practical E2E testing: the stream --token
value was written verbatim into the CLI startup log line.
"""

from megabasterd_cli.cli import _redacted_argv


def test_stream_token_value_is_redacted():
    argv = ["stream", "https://mega.nz/folder/ID#KEY", "-p", "8800", "--token", "s3cret-token"]
    out = _redacted_argv(argv)
    assert "s3cret-token" not in out
    assert out[out.index("--token") + 1] == "<redacted>"


def test_inline_token_form_is_redacted():
    out = _redacted_argv(["stream", "--token=s3cret-token"])
    assert "s3cret-token" not in " ".join(out)
    assert "--token=<redacted>" in out


def test_existing_sensitive_options_still_redacted():
    argv = [
        "download",
        "-p",
        "linkpw",
        "--vault-passphrase",
        "vp",
        "--mfa-code",
        "123456",
        "--elc-api-key",
        "apikey",
    ]
    out = _redacted_argv(argv)
    joined = " ".join(out)
    for secret in ("linkpw", "vp", "123456", "apikey"):
        assert secret not in joined
    assert out.count("<redacted>") == 4


def test_mega_link_redacted_and_plain_args_preserved():
    out = _redacted_argv(["download", "https://mega.nz/folder/ID#KEY", "-o", "out"])
    assert "<redacted-link>" in out
    assert "ID#KEY" not in " ".join(out)
    assert out[-2:] == ["-o", "out"]
