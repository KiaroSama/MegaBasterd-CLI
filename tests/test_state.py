"""Tests for resumable transfer state."""

import json
from pathlib import Path

from megabasterd_cli.core.state import (
    STATE_FORMAT_VERSION,
    TransferState,
    clear_state,
    load_state,
    save_state,
    state_path_for,
)


def test_save_and_load_roundtrip(tmp_path: Path):
    dest = tmp_path / "myfile.bin"
    # A download that has committed chunks always has a destination file: the
    # state vouches for those bytes. Creating it keeps the fixture faithful to
    # that rather than relaxing the durability rule to accommodate it.
    dest.write_bytes(b"\x00" * 1024)
    state = TransferState(
        transfer_type="download",
        source="https://example/x",
        destination=str(dest),
        total_size=1024,
    )
    state.mark_chunk_done(0, mac=b"\xaa" * 16)
    state.mark_chunk_done(1, mac=b"\xbb" * 16)
    save_state(state)

    loaded = load_state(dest)
    assert loaded is not None
    assert loaded.completed_chunks == [0, 1]
    assert loaded.get_chunk_mac(0) == b"\xaa" * 16
    assert loaded.get_chunk_mac(1) == b"\xbb" * 16


def test_missing_state_returns_none(tmp_path: Path):
    assert load_state(tmp_path / "doesnotexist") is None


def test_clear_state_removes_file(tmp_path: Path):
    dest = tmp_path / "x.bin"
    state = TransferState(
        transfer_type="download",
        source="x",
        destination=str(dest),
        total_size=10,
    )
    save_state(state)
    assert state_path_for(dest).exists()
    clear_state(dest)
    assert not state_path_for(dest).exists()


def test_state_file_has_format_version(tmp_path: Path):
    dest = tmp_path / "versioned.bin"
    state = TransferState(
        transfer_type="download",
        source="x",
        destination=str(dest),
        total_size=10,
    )

    save_state(state)
    raw = json.loads(state_path_for(dest).read_text(encoding="utf-8"))

    assert raw["format_version"] == STATE_FORMAT_VERSION
    assert load_state(dest).format_version == STATE_FORMAT_VERSION


def test_unsupported_state_version_returns_none(tmp_path: Path):
    dest = tmp_path / "future.bin"
    state = TransferState(
        transfer_type="download",
        source="x",
        destination=str(dest),
        total_size=10,
        format_version=999,
    )
    save_state(state)

    assert load_state(dest) is None
