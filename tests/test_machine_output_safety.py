"""MF1 + MF2: thread-safe atomic JSONL emit and central secret sanitization."""

from __future__ import annotations

import io
import json
import threading

import pytest

from megabasterd_cli.core.errors import QuotaError, TransferError
from megabasterd_cli.ui.machine_output import MachineOutput, error_code_for
from megabasterd_cli.utils.redaction import redact_text, sanitize


def _capture(monkeypatch) -> tuple[MachineOutput, io.StringIO]:
    buf = io.StringIO()
    m = MachineOutput(True)
    m._stream = buf
    return m, buf


def test_50_concurrent_threads_produce_valid_jsonl(monkeypatch):
    m, buf = _capture(monkeypatch)
    threads = [
        threading.Thread(target=lambda i=i: m.emit(event="result", n=i, blob="x" * 500))
        for i in range(60)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
        assert not t.is_alive()
    lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
    assert len(lines) == 60, "one complete line per record, no interleaving"
    seen = set()
    for ln in lines:
        rec = json.loads(ln)  # every line must be a complete, parseable object
        seen.add(rec["n"])
    assert seen == set(range(60)), "each record appears exactly once"


def test_mixed_success_failure_records_do_not_corrupt(monkeypatch):
    m, buf = _capture(monkeypatch)
    barrier = threading.Barrier(40)

    def worker(i: int) -> None:
        barrier.wait()
        if i % 2:
            m.emit(event="result", status="failed", error="boom " * 100, n=i)
        else:
            m.emit(event="result", status="success", name="f" * 100, n=i)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
    assert len(lines) == 40
    for ln in lines:
        json.loads(ln)


def test_sanitizer_redacts_mega_link_in_error(monkeypatch):
    m, buf = _capture(monkeypatch)
    m.emit(
        event="result",
        status="failed",
        error="failed on https://mega.nz/folder/ABC#SECRETKEYVALUE now",
    )
    rec = json.loads(buf.getvalue().strip())
    assert "SECRETKEYVALUE" not in buf.getvalue()
    assert "#<key>" in rec["error"]


def test_sanitizer_is_recursive_over_nested_structures(monkeypatch):
    m, buf = _capture(monkeypatch)
    m.emit(
        event="result",
        details={
            "accounts": {"host.example": {"user": "u", "api_key": "TOPSECRET"}},
            "links": ["https://mega.nz/file/X#NESTEDKEY"],
        },
    )
    out = buf.getvalue()
    assert "TOPSECRET" not in out
    assert "NESTEDKEY" not in out
    rec = json.loads(out.strip())
    assert rec["details"]["accounts"]["host.example"]["api_key"] == "<redacted>"
    assert rec["details"]["links"][0].endswith("#<key>")


def test_sanitizer_redacts_password_query_parameters():
    scrubbed = sanitize({"error": "GET /x?password=hunter2&token=abc123 failed"})
    assert "hunter2" not in scrubbed["error"]
    assert "abc123" not in scrubbed["error"]
    assert "password=<redacted>" in scrubbed["error"]


def test_secret_field_names_redacted_wholesale():
    out = sanitize({"vault_passphrase": "pw", "sid": "SESSION", "name": "ok"})
    assert out["vault_passphrase"] == "<redacted>"
    assert out["sid"] == "<redacted>"
    assert out["name"] == "ok"


def test_share_link_field_keeps_its_key():
    # A share link is intentional public output; only query secrets scrubbed.
    out = sanitize({"share_link": "https://mega.nz/file/H#PUBLICKEY"})
    assert out["share_link"] == "https://mega.nz/file/H#PUBLICKEY"


def test_error_codes_are_stable():
    assert error_code_for(QuotaError(message="x")) == "quota_exceeded"
    assert error_code_for(TransferError(message="x")) == "transfer_failed"
    assert error_code_for(FileNotFoundError("x")) == "local_file_missing"
    assert error_code_for(RuntimeError("x")) == "error"


def test_redact_text_handles_mega_scheme_wrappers():
    assert redact_text("mega://elc/token#KEYMATERIAL") == "mega://elc/token#<key>"


@pytest.mark.parametrize("enabled", [False])
def test_disabled_emitter_writes_nothing(enabled, monkeypatch):
    buf = io.StringIO()
    m = MachineOutput(enabled)
    m._stream = buf
    m.emit(event="result", status="success")
    assert buf.getvalue() == ""
