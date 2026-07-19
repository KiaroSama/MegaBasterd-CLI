"""The durability barrier must not fail OPEN when it cannot even be raised.

Sibling of `test_state_durability_failure.py`, which covers the fsync half.
This file covers the half before it: `os.open(destination, O_RDWR)`. Every
`OSError` there was logged at debug level and swallowed, after which
`save_state` committed a snapshot recording chunks as durable for a file it was
never able to touch. A barrier that cannot be raised is a barrier that failed.

The one tolerated case is a destination that does not exist yet AND a snapshot
with no completed chunks: it vouches for no bytes, so there is nothing to lose.
A missing destination with completed chunks is the corruption case, not the
harmless one - the file the state claims data for is gone.
"""

from __future__ import annotations

import errno
import os

import pytest

from megabasterd_cli.core.state import (
    StateDurabilityError,
    TransferState,
    load_state,
    save_state,
    state_path_for,
)

from .test_state_durability_failure import _committed, _state


def _assert_nothing_committed(destination, before, monkeypatch, exc):
    """Every open-failure case owes the same three guarantees."""
    replaces: list = []
    real_replace, real_open = os.replace, os.open
    monkeypatch.setattr(os, "replace", lambda *a, **kw: replaces.append(a))

    def _open(path, flags, *a, **kw):
        # Only the DESTINATION open fails; the state file's own lock and temp
        # file still need a working os.open, or the test proves nothing.
        if str(path) == str(destination):
            raise exc
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(os, "open", _open)

    with pytest.raises(StateDurabilityError):
        save_state(_state(destination, [1, 2, 3], revision=2))

    monkeypatch.setattr(os, "replace", real_replace)
    assert not replaces, "the state file was replaced after the destination open failed"
    assert state_path_for(destination).read_bytes() == before, "committed state changed"
    assert load_state(destination).completed_set == {1, 2}, "chunk 3 was wrongly recorded"


def test_a_permission_error_opening_the_destination_does_not_commit(tmp_path, monkeypatch):
    destination = tmp_path / "movie.mkv"
    destination.write_bytes(b"\x00" * 4096)
    before = _committed(destination, [1, 2])
    _assert_nothing_committed(destination, before, monkeypatch, PermissionError("locked"))


def test_an_eio_opening_the_destination_does_not_commit(tmp_path, monkeypatch):
    destination = tmp_path / "movie.mkv"
    destination.write_bytes(b"\x00" * 4096)
    before = _committed(destination, [1, 2])
    _assert_nothing_committed(
        destination, before, monkeypatch, OSError(errno.EIO, "Input/output error")
    )


def test_descriptor_exhaustion_opening_the_destination_does_not_commit(tmp_path, monkeypatch):
    destination = tmp_path / "movie.mkv"
    destination.write_bytes(b"\x00" * 4096)
    before = _committed(destination, [1, 2])
    _assert_nothing_committed(
        destination, before, monkeypatch, OSError(errno.EMFILE, "Too many open files")
    )


def test_a_successful_open_and_fsync_still_precede_the_state_replace(tmp_path, monkeypatch):
    """Guard the whole ordering: open -> fsync -> replace."""
    destination = tmp_path / "movie.mkv"
    destination.write_bytes(b"\x00" * 4096)

    order: list[str] = []
    real_open, real_fsync, real_replace = os.open, os.fsync, os.replace

    def _open(path, flags, *a, **kw):
        if str(path) == str(destination):
            order.append("open")
        return real_open(path, flags, *a, **kw)

    def _fsync(fd):
        order.append("fsync")
        return real_fsync(fd)

    def _replace(src, dst):
        order.append("replace")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "open", _open)
    monkeypatch.setattr(os, "fsync", _fsync)
    monkeypatch.setattr(os, "replace", _replace)

    save_state(_state(destination, [1]))

    assert "replace" in order, "nothing was committed"
    assert order.index("open") < order.index("fsync") < order.index("replace"), f"order: {order}"


def test_an_upload_never_opens_its_destination_for_a_flush(tmp_path, monkeypatch):
    """Uploads stay exempt: their durability point is the endpoint's HTTP 200."""
    source = tmp_path / "payload.bin"
    source.write_bytes(b"x" * 128)
    upload_destination = tmp_path / "payload.bin.upload"
    upload_destination.write_bytes(b"x" * 128)

    opened: list[str] = []
    real_open = os.open

    def _record_open(path, flags, *a, **kw):
        opened.append(str(path))
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(os, "open", _record_open)

    state = TransferState(
        transfer_type="upload",
        source=str(source),
        destination=str(upload_destination),
        total_size=128,
    )
    state.mark_chunk_done(0)

    save_state(state)  # must not raise

    assert str(upload_destination) not in opened, "an upload flushed a local destination"


def test_a_missing_destination_with_no_completed_chunks_is_tolerated(tmp_path):
    """Nothing is vouched for, so nothing can be lost - the one narrow exception."""
    destination = tmp_path / "not-created-yet.mkv"

    save_state(_state(destination, []))  # must not raise

    assert state_path_for(destination).exists()
    assert load_state(destination).completed_set == set()


def test_a_missing_destination_with_completed_chunks_raises(tmp_path, monkeypatch):
    """The state claims chunks for a file that is not there. That is the bug."""
    destination = tmp_path / "movie.mkv"
    destination.write_bytes(b"\x00" * 4096)
    before = _committed(destination, [1, 2])
    destination.unlink()

    replaces: list = []
    real_replace = os.replace
    monkeypatch.setattr(os, "replace", lambda *a, **kw: replaces.append(a))

    with pytest.raises(StateDurabilityError):
        save_state(_state(destination, [1, 2, 3], revision=2))

    monkeypatch.setattr(os, "replace", real_replace)
    assert not replaces, "the state file was replaced for a destination that is gone"
    assert state_path_for(destination).read_bytes() == before
