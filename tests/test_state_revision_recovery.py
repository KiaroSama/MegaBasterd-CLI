"""A DISCARDED `.mbstate` must not outrank the state that replaces it.

`save_state` refuses any snapshot older than the revision it reads off disk.
That guard is only sound while every file it reads is one `load_state` would
actually use: a rejected file left lying next to the destination carries an
arbitrarily high revision, and a fresh `TransferState` starts at 0, so every
save of the replacement transfer was dropped at `log.debug` level. A multi-hour
download wrote zero resume state and said nothing.

Three independent defenses, one test each:

1. `_quarantine_state` removes the original once its bytes are preserved
   (and keeps it when preservation failed - losing the evidence is worse).
2. `_disk_guard` validates the document, so a file that is not usable state
   constrains nothing - which is what its docstring always claimed.
3. The transfer code clears the state file on the branch where it decides not
   to reuse it, instead of leaving the loser on disk.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import megabasterd_cli.config as config_module
from megabasterd_cli.core.chunks import iter_chunks
from megabasterd_cli.core.downloader import MegaDownloader
from megabasterd_cli.core.errors import NonRetryableTransferError, TransferError
from megabasterd_cli.core.state import (
    STATE_FORMAT_VERSION,
    TransferState,
    _disk_guard,
    load_state,
    save_state,
    state_path_for,
)
from megabasterd_cli.core.uploader import MegaUploader

# Valid JSON, valid UTF-8, revision far ahead of any fresh transfer - and not a
# usable state document: `total_size` is missing, so `validate_state_dict`
# rejects it and `load_state` never returns it.
UNUSABLE_DOCUMENT = {
    "transfer_type": "download",
    "source": "stale-source",
    "destination": "stale-destination",
    "revision": 200,
}


def _write_raw_state(destination: Path, document: dict) -> Path:
    sp = state_path_for(destination)
    sp.write_text(json.dumps(document), encoding="utf-8")
    return sp


def _fresh_download_state(destination: Path, source: str = "our-source") -> TransferState:
    return TransferState(
        transfer_type="download",
        source=source,
        destination=str(destination),
        total_size=1024,
    )


# --------------------------------------------------------------------------
# 1. quarantine removes the original
# --------------------------------------------------------------------------


def test_quarantine_removes_the_original_after_preserving_it(tmp_path: Path):
    destination = tmp_path / "file.bin"
    sp = _write_raw_state(destination, UNUSABLE_DOCUMENT)

    assert load_state(destination) is None
    backups = list(tmp_path.glob(f"{sp.name}.corrupt.*"))
    assert len(backups) == 1, "the rejected bytes must still be preserved"
    assert not sp.exists(), "the rejected state file must not be left behind"


def test_quarantine_keeps_the_original_when_preservation_fails(tmp_path: Path, monkeypatch):
    """Losing the evidence is worse than leaving the file; `_disk_guard` copes."""
    import megabasterd_cli.utils.corruption as corruption

    monkeypatch.setattr(corruption, "preserve_corrupt_file", lambda path, data: None)
    destination = tmp_path / "file.bin"
    sp = _write_raw_state(destination, UNUSABLE_DOCUMENT)

    assert load_state(destination) is None
    assert sp.exists(), "an unpreserved file must not be deleted"


# --------------------------------------------------------------------------
# 2. _disk_guard ignores a document that is not usable state
# --------------------------------------------------------------------------


def test_disk_guard_ignores_a_document_that_is_not_valid_state(tmp_path: Path):
    destination = tmp_path / "file.bin"
    sp = _write_raw_state(destination, UNUSABLE_DOCUMENT)

    assert _disk_guard(sp) == (STATE_FORMAT_VERSION, -1)


def test_leftover_unusable_file_does_not_block_saves(tmp_path: Path):
    """The reproduction: revision 200 on disk, a revision-1 snapshot must land."""
    destination = tmp_path / "file.bin"
    destination.write_bytes(b"\0" * 1024)
    sp = _write_raw_state(destination, UNUSABLE_DOCUMENT)

    state = _fresh_download_state(destination)
    state.revision = 1
    save_state(state)

    persisted = json.loads(sp.read_text(encoding="utf-8"))
    assert persisted["source"] == "our-source"
    assert persisted["revision"] == 1


def test_a_newer_format_version_is_protected_without_validating_it(tmp_path: Path):
    """A v2 document owes nothing to v1's schema: version wins over validation.

    Validating before reading the version claim would hand `save_state` a
    permissive `(1, -1)` for a newer client's file and let it be overwritten.
    """
    destination = tmp_path / "file.bin"
    destination.write_bytes(b"\0" * 1024)
    sp = _write_raw_state(
        destination, {"format_version": STATE_FORMAT_VERSION + 1, "revision": 3, "fields": "new"}
    )

    save_state(_fresh_download_state(destination))

    assert json.loads(sp.read_text(encoding="utf-8"))["format_version"] == STATE_FORMAT_VERSION + 1


def test_a_valid_newer_revision_is_still_refused(tmp_path: Path):
    """The guard itself must survive: a REAL committed state still wins."""
    destination = tmp_path / "file.bin"
    destination.write_bytes(b"\0" * 1024)
    committed = _fresh_download_state(destination, source="committed-source")
    committed.revision = 200
    save_state(committed)

    stale = _fresh_download_state(destination, source="stale-worker")
    stale.revision = 1
    save_state(stale)

    persisted = json.loads(state_path_for(destination).read_text(encoding="utf-8"))
    assert persisted["source"] == "committed-source"


# --------------------------------------------------------------------------
# 3. the transfer clears the state file it decided not to reuse
# --------------------------------------------------------------------------


def test_download_persists_state_over_a_state_it_refused_to_resume(tmp_path: Path, monkeypatch):
    """A loadable but unusable state file (different source) must be cleared."""
    destination = tmp_path / "file.bin"
    file_size = 384 * 1024
    chunks = list(iter_chunks(file_size))
    assert len(chunks) > 1

    leftover = TransferState(
        transfer_type="download",
        source="a-completely-different-source",
        destination=str(destination),
        total_size=file_size,
        revision=200,
    )
    save_state(leftover)
    sp = state_path_for(destination)

    downloader = MegaDownloader(api=None, keep_state_files_on_error=True, verify_integrity=False)

    last_index = chunks[-1].index

    def fake_download_chunk(chunk, aes_key, nonce, dest, state):
        if chunk.index == last_index:
            raise NonRetryableTransferError(message="boom")
        with open(dest, "r+b") as f:
            f.seek(chunk.offset)
            f.write(b"\0" * chunk.size)
        with downloader._lock:
            state.mark_chunk_done(chunk.index, b"\xaa" * 16)
            downloader._bytes_done += chunk.size
            downloader._chunks_done += 1

    monkeypatch.setattr(downloader, "_download_chunk", fake_download_chunk)

    with pytest.raises(TransferError):
        downloader._run_download(
            cdn_url="https://example.invalid/cdn",
            file_size=file_size,
            aes_key=b"\x01" * 16,
            nonce=b"\x02" * 8,
            mac_iv_a32=[0, 0],
            destination=destination,
            source="our-source",
            on_progress=None,
        )

    assert sp.exists(), "an interrupted download must keep resume state"
    persisted = json.loads(sp.read_text(encoding="utf-8"))
    assert persisted["source"] == "our-source", "the discarded state file blocked every save"
    assert persisted["completed_chunks"] == [c.index for c in chunks[:-1]]


UPLOAD_URL = "https://gfs270n123.userstorage.mega.co.nz/ul/fake"


class _FakeResponse:
    def __init__(self, body: bytes = b"", status: int = 200):
        self.status_code = status
        self.content = body

    def iter_content(self, chunk_size: int = 65536):
        for start in range(0, len(self.content), chunk_size):
            yield self.content[start : start + chunk_size]

    def close(self) -> None:
        pass


def test_upload_refuses_a_foreign_version_state_without_deleting_it(tmp_path: Path, monkeypatch):
    """An unrecognized-version upload state must not be deleted.

    `load_state` leaves it on disk (it is foreign, not corrupt), and the upload
    REFUSES rather than clearing it - deleting it would throw away the progress
    of the client that wrote it. The download side of this is covered in
    `test_state_forward_compat.py`; the same-version clear-and-persist path (the
    round-21 S1 fix) is still exercised by
    `test_download_persists_state_over_a_state_it_refused_to_resume`.
    """
    monkeypatch.setattr(config_module, "data_dir", lambda: tmp_path / "data")
    file_size = 384 * 1024
    source = tmp_path / "file.bin"
    source.write_bytes(b"\x07" * file_size)

    state_path = MegaUploader._upload_state_destination(source)
    sp = state_path_for(state_path)
    sp.parent.mkdir(parents=True, exist_ok=True)
    newer = STATE_FORMAT_VERSION + 1
    sp.write_text(
        json.dumps(
            {
                "transfer_type": "upload",
                "source": str(source),
                "destination": str(state_path),
                "total_size": file_size,
                "format_version": newer,
                "revision": 500,
            }
        ),
        encoding="utf-8",
    )
    assert load_state(state_path) is None, "a foreign version must not be resumed"

    client = SimpleNamespace(
        session=SimpleNamespace(master_key=b"\x00" * 16),
        api=SimpleNamespace(request_upload=lambda size: {"p": UPLOAD_URL}),
        find_root=lambda: "root",
        invalidate_cache=lambda: None,
    )
    uploader = MegaUploader(client=client)

    with pytest.raises(TransferError, match=f"format version {newer}"):
        uploader.upload_file(source)

    assert sp.exists(), "a foreign-version upload state was deleted instead of refused"
    persisted = json.loads(sp.read_text(encoding="utf-8"))
    assert persisted["format_version"] == newer, "the foreign state was overwritten"
