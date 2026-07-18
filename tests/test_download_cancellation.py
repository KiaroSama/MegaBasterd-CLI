"""Cancelling a download is never success - even with integrity disabled.

The defect: `stop()` breaks out of the chunk-submission loop, and control then
fell through to `clear_state()` + `return DownloadResult(...)`. With
`verify_integrity=True` the MAC check happened to catch it; with
`verify_integrity=False` the caller was told the transfer SUCCEEDED, the
resume state was DELETED, and the reported size was the full file size.

Completion is now proven by chunk coverage, which does not depend on the
cryptographic integrity mode.
"""

from __future__ import annotations

import threading

import pytest

from megabasterd_cli.core.downloader import MegaDownloader
from megabasterd_cli.core.errors import TransferCancelled
from megabasterd_cli.core.state import load_state

FILE_SIZE = 1024 * 1024  # several chunks


def _fake_chunk_downloader(downloader: MegaDownloader, stop_after: int, done: list):
    """Complete `stop_after` chunks, then cancel mid-transfer."""
    real = downloader._download_chunk

    def instrumented(chunk, aes_key, nonce, destination, state):
        if downloader._stop_event.is_set():
            return real(chunk, aes_key, nonce, destination, state)
        if len(done) >= stop_after:
            downloader.stop()
            return real(chunk, aes_key, nonce, destination, state)
        done.append(chunk.index)
        return real(chunk, aes_key, nonce, destination, state)

    return instrumented


@pytest.fixture()
def offline_downloader(monkeypatch):
    """A downloader whose chunk fetch writes deterministic bytes, no network."""

    def fake_fetch(self, chunk, aes_key, nonce, destination, state):
        with self._lock:
            state.mark_chunk_done(chunk.index, b"\x11" * 16)
        return None

    monkeypatch.setattr(MegaDownloader, "_download_chunk", fake_fetch, raising=True)
    return fake_fetch


@pytest.mark.parametrize("verify_integrity", [True, False], ids=["verify-on", "verify-off"])
def test_cancelled_download_is_not_reported_as_success(tmp_path, monkeypatch, verify_integrity):
    destination = tmp_path / "out.bin"
    downloader = MegaDownloader(
        api=None, verify_integrity=verify_integrity, max_workers=1, auto_resume=True
    )

    started = threading.Event()

    def cancelling_chunk(chunk, aes_key, nonce, destination_, state):
        # Commit the first chunk, then cancel before the rest are fetched.
        if not started.is_set():
            started.set()
            with downloader._lock:
                state.mark_chunk_done(chunk.index, b"\x11" * 16)
            downloader.stop()
            return None
        return None

    monkeypatch.setattr(downloader, "_download_chunk", cancelling_chunk)

    with pytest.raises(TransferCancelled):
        downloader._run_download(
            cdn_url="https://cdn.invalid/x",
            file_size=FILE_SIZE,
            aes_key=b"\x00" * 16,
            nonce=b"\x00" * 8,
            mac_iv_a32=(0, 0, 0, 0),
            destination=destination,
            source="https://mega.nz/file/ID#<key>",
            on_progress=None,
        )


@pytest.mark.parametrize("verify_integrity", [True, False], ids=["verify-on", "verify-off"])
def test_cancelled_download_keeps_resume_state(tmp_path, monkeypatch, verify_integrity):
    """State must survive so the transfer can actually resume."""
    destination = tmp_path / "out.bin"
    downloader = MegaDownloader(
        api=None,
        verify_integrity=verify_integrity,
        max_workers=1,
        auto_resume=True,
        keep_state_files_on_error=True,
    )

    started = threading.Event()

    def cancelling_chunk(chunk, aes_key, nonce, destination_, state):
        if not started.is_set():
            started.set()
            with downloader._lock:
                state.mark_chunk_done(chunk.index, b"\x11" * 16)
            downloader.stop()
        return None

    monkeypatch.setattr(downloader, "_download_chunk", cancelling_chunk)

    with pytest.raises(TransferCancelled):
        downloader._run_download(
            cdn_url="https://cdn.invalid/x",
            file_size=FILE_SIZE,
            aes_key=b"\x00" * 16,
            nonce=b"\x00" * 8,
            mac_iv_a32=(0, 0, 0, 0),
            destination=destination,
            source="https://mega.nz/file/ID#<key>",
            on_progress=None,
        )

    state = load_state(destination)
    assert state is not None, "cancellation must not delete the resume state"
    assert state.completed_chunks, "the committed chunk must still be recorded"


def test_cancellation_before_any_chunk_completes(tmp_path, monkeypatch):
    """Cancelled with ZERO chunks committed.

    `_run_download` clears the stop event on entry so a downloader object can
    be reused for the next file, so cancellation is signalled during the run -
    which is exactly what a Ctrl-C handler does.
    """
    destination = tmp_path / "out.bin"
    downloader = MegaDownloader(api=None, verify_integrity=False, max_workers=1)

    def cancel_immediately(chunk, aes_key, nonce, destination_, state):
        downloader.stop()  # nothing is ever committed
        return None

    monkeypatch.setattr(downloader, "_download_chunk", cancel_immediately)

    with pytest.raises(TransferCancelled):
        downloader._run_download(
            cdn_url="https://cdn.invalid/x",
            file_size=FILE_SIZE,
            aes_key=b"\x00" * 16,
            nonce=b"\x00" * 8,
            mac_iv_a32=(0, 0, 0, 0),
            destination=destination,
            source="https://mega.nz/file/ID#<key>",
            on_progress=None,
        )


def test_incomplete_coverage_without_cancellation_is_also_a_failure(tmp_path, monkeypatch):
    """A worker that silently skips a chunk must not yield success either."""
    destination = tmp_path / "out.bin"
    downloader = MegaDownloader(api=None, verify_integrity=False, max_workers=1)

    def skip_one(chunk, aes_key, nonce, destination_, state):
        if chunk.index == 0:
            return None  # silently does nothing
        with downloader._lock:
            state.mark_chunk_done(chunk.index, b"\x11" * 16)
        return None

    monkeypatch.setattr(downloader, "_download_chunk", skip_one)

    with pytest.raises(Exception) as caught:  # noqa: B017
        downloader._run_download(
            cdn_url="https://cdn.invalid/x",
            file_size=FILE_SIZE,
            aes_key=b"\x00" * 16,
            nonce=b"\x00" * 8,
            mac_iv_a32=(0, 0, 0, 0),
            destination=destination,
            source="https://mega.nz/file/ID#<key>",
            on_progress=None,
        )
    assert "incomplete" in str(caught.value).lower() or "chunk" in str(caught.value).lower()


def test_cancellation_is_distinguishable_from_a_transfer_error():
    """Callers (machine output, exit codes) must be able to tell them apart."""
    from megabasterd_cli.core.errors import MegaError, TransferError

    assert issubclass(TransferCancelled, TransferError)
    assert issubclass(TransferCancelled, MegaError)
    assert TransferCancelled is not TransferError


def test_error_code_for_cancellation_is_distinct():
    from megabasterd_cli.ui.machine_output import error_code_for

    assert error_code_for(TransferCancelled(message="stopped")) == "cancelled"
