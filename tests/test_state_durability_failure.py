"""A state file must never outlive the data it vouches for.

`save_state` fsyncs the state file, so after a crash the state can easily
survive when the destination bytes did not. Resume then SKIPS chunks whose
data never reached the platter and silently produces a wrong file - the exact
failure the flush was added to prevent.

The flush was there, but a *failed* fsync only logged a warning and returned,
after which `save_state` went right on committing a snapshot claiming those
chunks were durable. A failed durability barrier that lets the commit proceed
is not a barrier.

Item 2 is the sibling: the `os.replace` retry loop left its temp file behind
on every failure path, so a destination held open by antivirus accumulated
`.mbstate.*.tmp` orphans next to the download.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from megabasterd_cli.core.state import (
    StateDurabilityError,
    TransferState,
    load_state,
    save_state,
    state_path_for,
)


def _state(destination: Path, chunks: list[int], revision: int = 1) -> TransferState:
    state = TransferState(
        transfer_type="download",
        source="https://mega.invalid/file/X",
        destination=str(destination),
        total_size=4096,
        revision=revision,
    )
    for index in chunks:
        state.mark_chunk_done(index)
    return state


def _committed(destination: Path, chunks: list[int]) -> bytes:
    """Put a known-good state on disk and return its exact bytes."""
    save_state(_state(destination, chunks, revision=1))
    return state_path_for(destination).read_bytes()


def _temps(destination: Path) -> list[Path]:
    return list(destination.parent.glob("*.tmp"))


# ---------------------------------------------------------------------------
# Item 1 - a failed data fsync must not be followed by a state commit
# ---------------------------------------------------------------------------


def test_a_failed_data_fsync_does_not_commit_the_state(tmp_path, monkeypatch):
    destination = tmp_path / "movie.mkv"
    destination.write_bytes(b"\x00" * 4096)
    before = _committed(destination, [1, 2])

    replaces: list = []
    real_replace = os.replace
    monkeypatch.setattr(os, "replace", lambda *a, **kw: replaces.append(a))

    def _fsync_fails(fd):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(os, "fsync", _fsync_fails)

    with pytest.raises(StateDurabilityError):
        save_state(_state(destination, [1, 2, 3], revision=2))

    monkeypatch.setattr(os, "replace", real_replace)
    assert not replaces, "the state file was replaced after the data fsync failed"
    assert state_path_for(destination).read_bytes() == before, "committed state changed"
    assert load_state(destination).completed_set == {1, 2}, "chunk 3 was wrongly recorded"


def test_the_durability_failure_is_typed_and_actionable(tmp_path, monkeypatch):
    """The caller has to be able to tell this apart from a lock timeout."""
    from megabasterd_cli.core.errors import MegaError

    destination = tmp_path / "movie.mkv"
    destination.write_bytes(b"\x00" * 4096)

    monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError(28, "No space")))

    with pytest.raises(StateDurabilityError) as caught:
        save_state(_state(destination, [1]))

    assert isinstance(caught.value, MegaError), "must be catchable as a MegaError"
    assert "No space" in str(caught.value) or "28" in str(caught.value)


def test_a_successful_fsync_still_precedes_the_state_replace(tmp_path, monkeypatch):
    """Guard the ordering itself, not just the failure path."""
    destination = tmp_path / "movie.mkv"
    destination.write_bytes(b"\x00" * 4096)

    order: list[str] = []
    real_fsync, real_replace = os.fsync, os.replace

    def _fsync(fd):
        order.append("fsync")
        return real_fsync(fd)

    def _replace(src, dst):
        order.append("replace")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "fsync", _fsync)
    monkeypatch.setattr(os, "replace", _replace)

    save_state(_state(destination, [1]))

    assert "replace" in order, "nothing was committed"
    assert order.index("fsync") < order.index("replace"), f"wrong order: {order}"


def test_an_upload_is_unaffected_by_the_destination_flush(tmp_path, monkeypatch):
    """An upload's durability point is the endpoint's 200, not a local fsync.

    Asserted by watching `os.open`, not by breaking `os.fsync`: the state file
    legitimately fsyncs itself, so failing fsync globally would prove nothing
    about whether the DESTINATION flush was skipped.
    """
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


# ---------------------------------------------------------------------------
# Item 2 - no temp file may survive a failed replace
# ---------------------------------------------------------------------------


def test_a_permission_error_through_every_retry_leaves_no_temp(tmp_path, monkeypatch):
    destination = tmp_path / "movie.mkv"
    destination.write_bytes(b"\x00" * 4096)
    before = _committed(destination, [1])

    monkeypatch.setattr(
        os, "replace", lambda *a, **kw: (_ for _ in ()).throw(PermissionError("locked"))
    )
    monkeypatch.setattr("megabasterd_cli.core.state.time.sleep", lambda s: None)

    with pytest.raises(PermissionError):
        save_state(_state(destination, [1, 2], revision=2))

    assert _temps(destination) == [], f"orphaned temp files: {_temps(destination)}"
    assert state_path_for(destination).read_bytes() == before


def test_a_generic_oserror_leaves_no_temp(tmp_path, monkeypatch):
    destination = tmp_path / "movie.mkv"
    destination.write_bytes(b"\x00" * 4096)
    before = _committed(destination, [1])

    monkeypatch.setattr(
        os, "replace", lambda *a, **kw: (_ for _ in ()).throw(OSError(28, "No space left"))
    )

    with pytest.raises(OSError):
        save_state(_state(destination, [1, 2], revision=2))

    assert _temps(destination) == [], f"orphaned temp files: {_temps(destination)}"
    assert state_path_for(destination).read_bytes() == before


def test_an_interrupt_during_replace_leaves_no_temp(tmp_path, monkeypatch):
    destination = tmp_path / "movie.mkv"
    destination.write_bytes(b"\x00" * 4096)
    _committed(destination, [1])

    monkeypatch.setattr(os, "replace", lambda *a, **kw: (_ for _ in ()).throw(KeyboardInterrupt()))

    with pytest.raises(KeyboardInterrupt):
        save_state(_state(destination, [1, 2], revision=2))

    assert _temps(destination) == [], f"orphaned temp files: {_temps(destination)}"


def test_a_successful_save_leaves_no_temp(tmp_path):
    destination = tmp_path / "movie.mkv"
    destination.write_bytes(b"\x00" * 4096)

    save_state(_state(destination, [1, 2]))

    assert _temps(destination) == []
    assert state_path_for(destination).exists()


def test_a_failed_replace_never_removes_the_live_state(tmp_path, monkeypatch):
    destination = tmp_path / "movie.mkv"
    destination.write_bytes(b"\x00" * 4096)
    before = _committed(destination, [1, 2, 3])

    monkeypatch.setattr(os, "replace", lambda *a, **kw: (_ for _ in ()).throw(OSError("nope")))

    with pytest.raises(OSError):
        save_state(_state(destination, [1, 2, 3, 4], revision=2))

    assert state_path_for(destination).exists(), "the live state file was destroyed"
    assert state_path_for(destination).read_bytes() == before
