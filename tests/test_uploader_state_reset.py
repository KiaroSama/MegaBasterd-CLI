"""MF4: per-file uploader cancellation/state reset between files."""

from __future__ import annotations

import contextlib
from types import SimpleNamespace

import megabasterd_cli.config as config_module
import megabasterd_cli.core.uploader as uploader_module
from megabasterd_cli.core.uploader import MegaUploader


class _FakeResponse:
    def __init__(self, body: bytes = b"TOKEN"):
        self.status_code = 200
        self.content = body

    def close(self) -> None:
        pass


class _DummyAPI:
    def request_upload(self, size: int) -> dict:
        return {"p": "http://fake.invalid/upload"}

    def complete_upload(self, **kwargs) -> dict:
        return {"f": [{"h": "H"}]}


def _client():
    return SimpleNamespace(
        session=SimpleNamespace(master_key=b"\x00" * 16),
        api=_DummyAPI(),
        find_root=lambda: "root",
        invalidate_cache=lambda: None,
    )


def test_stop_event_is_cleared_before_next_file(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "data_dir", lambda: tmp_path / "data")
    monkeypatch.setattr(
        uploader_module.requests,
        "post",
        lambda *a, **k: _FakeResponse(),
    )
    up = MegaUploader(client=_client())
    # Simulate a prior file that set the stop event (a failed chunk).
    up._stop_event.set()
    up._bytes_done = 999
    up._chunks_done = 7
    up._completion_token = b"STALE"

    src = tmp_path / "b.bin"
    src.write_bytes(b"\x01" * 4096)
    # Without the reset, hashing would abort with "canceled while hashing".
    result = up.upload_file(src)
    assert result.size == 4096
    assert up._completion_token != b"STALE"


def test_first_file_failure_does_not_poison_second(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "data_dir", lambda: tmp_path / "data")

    calls = {"n": 0}

    def flaky_post(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            # First file's chunk sets stop via a raised error in the worker.
            raise uploader_module.requests.ConnectionError("boom")
        return _FakeResponse()

    monkeypatch.setattr(uploader_module.requests, "post", flaky_post)
    up = MegaUploader(client=_client(), max_workers=1)

    first = tmp_path / "first.bin"
    first.write_bytes(b"\x02" * 2048)
    second = tmp_path / "second.bin"
    second.write_bytes(b"\x03" * 2048)

    # First upload fails after retries (ConnectionError).
    with contextlib.suppress(Exception):
        up.upload_file(first)
    # Second upload must start cleanly (state reset, event cleared).
    result = up.upload_file(second)
    assert result.size == 2048


def test_completion_token_does_not_leak_between_files(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "data_dir", lambda: tmp_path / "data")
    monkeypatch.setattr(uploader_module.requests, "post", lambda *a, **k: _FakeResponse(b"TOKEN-A"))
    up = MegaUploader(client=_client())
    a = tmp_path / "a.bin"
    a.write_bytes(b"\x04" * 1024)
    up.upload_file(a)
    token_after_a = up._completion_token
    # A fresh call resets the token before it is set again by this file.
    up._reset_per_file_state()
    assert up._completion_token is None
    assert token_after_a is not None
