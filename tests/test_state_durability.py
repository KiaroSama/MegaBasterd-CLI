"""Ordering, durability and metadata safety of `.mbstate` files.

Historical defects covered here:

A1 - `mark_chunk_done` accepted a MAC of any length, so the WRITE path could
     produce a file the READ path quarantines: one bad MAC cost the whole
     resume state. Saves had no generation number, so an older worker snapshot
     could overwrite a newer commit and un-complete chunks. The downloaded
     bytes were never fsynced, so the state file could outlive the data it
     vouches for. `clear_state` unlinked outside the save lock.

B2 - `metadata` was validated only as "is a dict". The uploader then read
     `aes_key`/`nonce`/`completion_token` through `bytes.fromhex` (which raises
     TypeError, not ValueError, for a JSON number - escaping the uploader's
     self-heal) and POSTed the whole local file to whatever `upload_url` said.
"""

from __future__ import annotations

import json
import os

import pytest

import megabasterd_cli.core.state as state_module
from megabasterd_cli.core.state import (
    StateCorruptionError,
    TransferState,
    clear_state,
    load_state,
    save_state,
    snapshot_state,
    state_path_for,
    validate_state_dict,
)

MAC = b"\xaa" * 16
UPLOAD_URL = "https://gfs270n123.userstorage.mega.co.nz/ul/fake"


def _download_state(destination, **overrides) -> TransferState:
    kwargs = {
        "transfer_type": "download",
        "source": "https://mega.nz/file/ID#<key>",
        "destination": str(destination),
        "total_size": 4096,
    }
    kwargs.update(overrides)
    return TransferState(**kwargs)


def _upload_doc(**metadata_overrides) -> dict:
    metadata = {
        "upload_url": UPLOAD_URL,
        "aes_key": bytes(range(16)).hex(),
        "nonce": bytes(range(8)).hex(),
        "completion_token": b"TOKEN".hex(),
    }
    metadata.update(metadata_overrides)
    return {
        "transfer_type": "upload",
        "source": "/local/file.bin",
        "destination": "/state/file.upload",
        "total_size": 1024,
        "format_version": 1,
        "completed_chunks": [],
        "chunk_macs": {},
        "metadata": metadata,
    }


# --------------------------------------------------------------------------
# A1.1 - the write path rejects what the read path would quarantine
# --------------------------------------------------------------------------


@pytest.mark.parametrize("mac", [b"", b"\xaa" * 15, b"\xaa" * 17, b"\xaa" * 32])
def test_mark_chunk_done_rejects_a_wrong_length_mac(tmp_path, mac):
    state = _download_state(tmp_path / "out.bin")
    with pytest.raises(StateCorruptionError):
        state.mark_chunk_done(0, mac)
    assert state.completed_chunks == [], "a rejected MAC must not half-complete the chunk"


def test_mark_chunk_done_still_accepts_a_16_byte_mac_and_no_mac(tmp_path):
    state = _download_state(tmp_path / "out.bin")
    state.mark_chunk_done(0, MAC)
    state.mark_chunk_done(1)
    assert state.completed_chunks == [0, 1]
    assert state.get_chunk_mac(0) == MAC


def test_a_bad_mac_no_longer_destroys_the_whole_resume_state(tmp_path):
    """Before: the short MAC was stored, and load_state quarantined everything."""
    destination = tmp_path / "out.bin"
    state = _download_state(destination)
    state.mark_chunk_done(0, MAC)
    save_state(state)
    with pytest.raises(StateCorruptionError):
        state.mark_chunk_done(1, b"\xbb" * 8)
    reloaded = load_state(destination)
    assert reloaded is not None, "earlier progress must survive a rejected MAC"
    assert reloaded.completed_chunks == [0]


# --------------------------------------------------------------------------
# A1.2 - a stale snapshot can never overwrite a newer commit
# --------------------------------------------------------------------------


def test_an_older_snapshot_never_overwrites_a_newer_commit(tmp_path):
    destination = tmp_path / "out.bin"
    state = _download_state(destination)

    state.mark_chunk_done(0, MAC)
    stale = snapshot_state(state)  # worker A's view
    state.mark_chunk_done(1, MAC)
    state.metadata["nonce"] = bytes(range(8)).hex()
    fresh = snapshot_state(state)  # worker B's view

    save_state(fresh)
    save_state(stale)  # arrives late; must be refused

    reloaded = load_state(destination)
    assert reloaded is not None
    assert sorted(reloaded.completed_chunks) == [0, 1], "completed chunks regressed"
    assert reloaded.get_chunk_mac(1) == MAC, "a committed MAC regressed"
    assert reloaded.metadata.get("nonce"), "committed metadata regressed"
    assert reloaded.revision == fresh.revision


def test_snapshots_take_strictly_increasing_revisions(tmp_path):
    state = _download_state(tmp_path / "out.bin")
    revisions = [snapshot_state(state).revision for _ in range(3)]
    assert revisions == sorted(set(revisions)) and len(revisions) == 3


def test_resaving_the_same_snapshot_is_allowed(tmp_path):
    """The downloader saves one `committed` snapshot twice on its error path."""
    destination = tmp_path / "out.bin"
    state = _download_state(destination)
    state.mark_chunk_done(0, MAC)
    committed = snapshot_state(state)
    save_state(committed)
    save_state(committed)
    assert load_state(destination).completed_chunks == [0]


# --------------------------------------------------------------------------
# A1.3 - the data is on disk before the state claims it
# --------------------------------------------------------------------------


def test_download_data_is_fsynced_before_the_state_file_is_replaced(tmp_path, monkeypatch):
    destination = tmp_path / "out.bin"
    destination.write_bytes(b"\x5a" * 4096)
    st = destination.stat()
    if not st.st_ino:
        pytest.skip("filesystem does not report a usable file id")
    identity = (st.st_dev, st.st_ino)

    events: list[str] = []
    real_fsync, real_replace = os.fsync, os.replace

    def spy_fsync(fd):
        try:
            fst = os.fstat(fd)
            same = (fst.st_dev, fst.st_ino) == identity
        except OSError:
            same = False
        events.append("fsync-data" if same else "fsync-state")
        return real_fsync(fd)

    def spy_replace(src, dst):
        events.append("replace-state")
        return real_replace(src, dst)

    monkeypatch.setattr(state_module.os, "fsync", spy_fsync)
    monkeypatch.setattr(state_module.os, "replace", spy_replace)

    state = _download_state(destination)
    state.mark_chunk_done(0, MAC)
    save_state(state)

    assert "fsync-data" in events, "the downloaded bytes were never flushed to disk"
    assert events.index("fsync-data") < events.index("replace-state")


# --------------------------------------------------------------------------
# A1.4 - clear_state uses the save lock, and keeps the lock sidecar
# --------------------------------------------------------------------------


def test_clear_state_does_not_unlink_while_a_writer_holds_the_lock(tmp_path, monkeypatch):
    from megabasterd_cli.utils.filelock import FileLock

    monkeypatch.setattr(state_module, "STATE_LOCK_TIMEOUT", 0.2)
    destination = tmp_path / "out.bin"
    state = _download_state(destination)
    save_state(state)
    sp = state_path_for(destination)

    holder = FileLock(sp.parent / (sp.name + ".lock"))
    holder.acquire(timeout=1.0)
    try:
        clear_state(destination)
        assert sp.exists(), "clear_state removed the state file behind an active writer"
    finally:
        holder.release()

    clear_state(destination)
    assert not sp.exists(), "clear_state must remove the state once the lock is free"


def test_clear_state_keeps_the_inert_lock_sidecar(tmp_path):
    """Unlinking a live lock name re-creates the inode race documented in
    `utils/helpers.release_destination`: two processes end up locking two
    different inodes under one name."""
    destination = tmp_path / "out.bin"
    save_state(_download_state(destination))
    sp = state_path_for(destination)
    clear_state(destination)
    assert not sp.exists()
    assert (sp.parent / (sp.name + ".lock")).exists()


# --------------------------------------------------------------------------
# A1.5 - a FUTURE format version is never overwritten
# --------------------------------------------------------------------------


def test_save_state_refuses_to_overwrite_a_future_format_version(tmp_path):
    destination = tmp_path / "out.bin"
    sp = state_path_for(destination)
    future = json.dumps(
        {
            "transfer_type": "download",
            "source": "s",
            "destination": str(destination),
            "total_size": 4096,
            "format_version": state_module.STATE_FORMAT_VERSION + 5,
            "completed_chunks": [0, 1, 2],
            "chunk_macs": {},
            "metadata": {},
        }
    )
    sp.write_text(future, encoding="utf-8")

    state = _download_state(destination)
    state.mark_chunk_done(0, MAC)
    save_state(state)

    assert sp.read_text(encoding="utf-8") == future, "a newer client's state was destroyed"


def test_clear_state_keeps_a_future_format_version(tmp_path):
    destination = tmp_path / "out.bin"
    sp = state_path_for(destination)
    sp.write_text(json.dumps({"format_version": 99}), encoding="utf-8")
    clear_state(destination)
    assert sp.exists(), "a newer client's state must not be deleted either"


# --------------------------------------------------------------------------
# B2 - metadata is validated at load, not exploded on later
# --------------------------------------------------------------------------

BAD_METADATA = {
    "aes-key-is-a-number": {"aes_key": 1234},
    "aes-key-is-null": {"aes_key": None},
    "aes-key-too-short": {"aes_key": "aabb"},
    "aes-key-not-hex": {"aes_key": "zz" * 16},
    "nonce-is-a-list": {"nonce": []},
    "nonce-wrong-length": {"nonce": "aa" * 16},
    "nonce-not-hex": {"nonce": "zzzzzzzzzzzzzzzz"},
    "token-is-a-number": {"completion_token": 42},
    "token-not-hex": {"completion_token": "nothex!!"},
    "token-odd-length": {"completion_token": "abc"},
    "token-oversized": {"completion_token": "aa" * 9000},
    "url-is-a-number": {"upload_url": 8080},
    "url-plain-http": {"upload_url": "http://gfs.userstorage.mega.co.nz/ul"},
    "url-loopback": {"upload_url": "https://127.0.0.1/ul"},
    "url-metadata-service": {"upload_url": "https://169.254.169.254/ul"},
    "url-with-credentials": {"upload_url": "https://a:b@gfs.userstorage.mega.co.nz/ul"},
    "url-attacker-host": {"upload_url": "https://attacker.example/ul"},
    "url-lookalike-host": {"upload_url": "https://mega.co.nz.attacker.example/ul"},
    "source-identity-not-a-dict": {"source_identity": "trust me"},
}


@pytest.mark.parametrize("metadata", list(BAD_METADATA.values()), ids=list(BAD_METADATA))
def test_bad_metadata_raises_state_corruption_error(metadata):
    with pytest.raises(StateCorruptionError):
        validate_state_dict(_upload_doc(**metadata))


@pytest.mark.parametrize("metadata", list(BAD_METADATA.values()), ids=list(BAD_METADATA))
def test_bad_metadata_is_quarantined_at_load_not_raised_at_use(tmp_path, metadata):
    """A JSON-number `aes_key` used to survive load and then raise a raw
    TypeError out of `bytes.fromhex` - which the uploader's
    `except (KeyError, ValueError)` self-heal did not catch, so the poisoned
    file broke every later retry."""
    destination = tmp_path / "out.bin"
    path = state_path_for(destination)
    doc = _upload_doc(**metadata)
    doc["destination"] = str(destination)
    payload = json.dumps(doc)
    path.write_text(payload, encoding="utf-8")

    assert load_state(destination) is None  # must not raise
    backups = list(tmp_path.glob("out.bin.mbstate.corrupt.*"))
    assert len(backups) == 1 and backups[0].read_text(encoding="utf-8") == payload


def test_valid_upload_metadata_still_loads(tmp_path):
    destination = tmp_path / "out.bin"
    doc = _upload_doc()
    doc["destination"] = str(destination)
    state_path_for(destination).write_text(json.dumps(doc), encoding="utf-8")

    state = load_state(destination)
    assert state is not None
    assert state.metadata["upload_url"] == UPLOAD_URL
    assert bytes.fromhex(state.metadata["aes_key"]) == bytes(range(16))
    assert not list(tmp_path.glob("out.bin.mbstate.corrupt.*"))


def test_a_download_state_round_trips_its_metadata(tmp_path):
    destination = tmp_path / "out.bin"
    state = _download_state(
        destination,
        metadata={"aes_key": bytes(range(16)).hex(), "nonce": bytes(range(8)).hex()},
    )
    save_state(state)
    reloaded = load_state(destination)
    assert reloaded is not None and reloaded.metadata["nonce"] == bytes(range(8)).hex()
