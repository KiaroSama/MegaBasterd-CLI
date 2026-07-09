"""Upload progress speed semantics (mirror of the downloader's fix).

The uploader used to report ``bytes_done / elapsed_since_start`` — a lifetime
average whose ``bytes_done`` is pre-seeded with already-uploaded chunks, so a
resumed upload's first report showed absurdly inflated speeds. Speed must come
from a rolling window that treats the resumed byte count as a baseline.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import megabasterd_cli.config as config_module
import megabasterd_cli.core.uploader as uploader_module
from megabasterd_cli.core.chunks import iter_chunks
from megabasterd_cli.core.state import TransferState, save_state
from megabasterd_cli.core.uploader import MegaUploader

UPLOAD_URL = "http://fake.invalid/upload"


class _FakeResponse:
    def __init__(self, body: bytes = b""):
        self.status_code = 200
        self.content = body

    def close(self) -> None:
        pass


class _DummyAPI:
    def request_upload(self, size: int) -> dict:
        return {"p": UPLOAD_URL}

    def complete_upload(self, **kwargs) -> dict:
        return {"f": [{"h": "HANDLE"}]}


def _dummy_client() -> SimpleNamespace:
    return SimpleNamespace(
        session=SimpleNamespace(master_key=b"\x00" * 16),
        api=_DummyAPI(),
        find_root=lambda: "root",
        invalidate_cache=lambda: None,
    )


def test_resumed_upload_speed_excludes_resumed_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "data_dir", lambda: tmp_path / "data")

    # 8 MEGA chunks (128K..1M); everything but the FIRST chunk was uploaded
    # in an earlier session, so resumed bytes dwarf the one pending chunk.
    file_size = sum(c.size for c in iter_chunks(4_718_592))
    source = tmp_path / "big.bin"
    source.write_bytes(b"\x07" * file_size)
    chunks = list(iter_chunks(file_size))
    pending_chunk = chunks[0]
    resumed_bytes = file_size - pending_chunk.size

    aes_key = bytes(range(16))
    nonce = bytes(range(8))
    state_path = MegaUploader._upload_state_destination(source)
    state = TransferState(
        transfer_type="upload",
        source=str(source),
        destination=str(state_path),
        total_size=file_size,
        metadata={
            "upload_url": UPLOAD_URL,
            "aes_key": aes_key.hex(),
            "nonce": nonce.hex(),
            "completion_token": b"TOKEN".hex(),
        },
    )
    for chunk in chunks[1:]:
        state.mark_chunk_done(chunk.index, b"\x00" * 16)
    save_state(state)

    def fake_post(url, data=b"", timeout=None, proxies=None):
        time.sleep(0.35)  # deterministic transfer duration for the rate check
        return _FakeResponse(b"")

    monkeypatch.setattr(uploader_module.requests, "post", fake_post)

    uploader = MegaUploader(client=_dummy_client(), max_workers=2)
    reports = []
    lock = threading.Lock()

    def on_progress(p):
        with lock:
            reports.append(p)

    result = uploader.upload_file(source, on_progress=on_progress)

    assert result.size == file_size
    assert reports, "no progress reports were emitted"
    assert reports[-1].bytes_done == file_size
    # The lifetime-average formula reports ~(resumed+new)/elapsed here
    # (~13 MB/s); a windowed rate that excludes the resume baseline can only
    # ever see the single pending 128 KiB chunk.
    max_speed = max(p.speed_bps for p in reports)
    assert max_speed < pending_chunk.size * 4, (
        f"reported speed {max_speed:.0f} B/s counts resumed bytes "
        f"({resumed_bytes} resumed, {pending_chunk.size} actually uploaded)"
    )
