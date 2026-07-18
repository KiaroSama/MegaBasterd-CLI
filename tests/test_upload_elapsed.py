"""Upload result elapsed semantics.

Historical bug: `_start_time` was reset inside the upload-slot retry loop, so
the result elapsed silently excluded failed first attempts; finalization time
was also not consistently included.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import megabasterd_cli.config as config_module
import megabasterd_cli.core.uploader as uploader_module
from megabasterd_cli.core.uploader import MegaUploader

UPLOAD_URL = "http://fake.invalid/upload"


class _FakeResponse:
    def __init__(self, body: bytes = b"", status: int = 200):
        self.status_code = status
        self.content = body

    def iter_content(self, chunk_size: int = 65536):
        for start in range(0, len(self.content), chunk_size):
            yield self.content[start : start + chunk_size]

    def close(self) -> None:
        pass


class _SlowFinalizeAPI:
    def __init__(self, finalize_delay: float = 0.0):
        self.finalize_delay = finalize_delay
        self.slots = 0

    def request_upload(self, size: int) -> dict:
        self.slots += 1
        return {"p": UPLOAD_URL}

    def complete_upload(self, **kwargs) -> dict:
        time.sleep(self.finalize_delay)
        return {"f": [{"h": "HANDLE"}]}


def _client(api) -> SimpleNamespace:
    return SimpleNamespace(
        session=SimpleNamespace(master_key=b"\x00" * 16),
        api=api,
        find_root=lambda: "root",
        invalidate_cache=lambda: None,
    )


def test_elapsed_includes_failed_slot_and_retry_and_finalization(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "data_dir", lambda: tmp_path / "data")
    source = tmp_path / "f.bin"
    source.write_bytes(b"\x01" * 1024)

    calls = {"n": 0}

    def fake_post(url, data=b"", timeout=None, proxies=None, headers=None, stream=False):
        calls["n"] += 1
        if calls["n"] == 1:
            time.sleep(0.15)  # time spent on the DOOMED first slot
            return _FakeResponse(status=403)  # upload URL expired
        time.sleep(0.1)
        return _FakeResponse(b"TOKEN")

    monkeypatch.setattr(uploader_module.requests, "post", fake_post)
    api = _SlowFinalizeAPI(finalize_delay=0.2)
    uploader = MegaUploader(client=_client(api), max_workers=1)

    start = time.monotonic()
    result = uploader.upload_file(source)
    wall = time.monotonic() - start

    assert api.slots == 2, "the first slot expired and was refreshed"
    # Elapsed must cover the failed attempt (0.15s) + retry (0.1s) +
    # finalization (0.2s); the old reset-inside-the-loop behavior reported
    # only ~0.1s here.
    assert result.elapsed_seconds >= 0.4
    # And it must agree with the real wall time (tolerance for overhead).
    assert abs(result.elapsed_seconds - wall) < 0.5
