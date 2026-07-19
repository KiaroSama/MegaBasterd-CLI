"""`.mbstate` files are fully validated, quarantined, and cross-process safe.

Valid JSON is not valid resume state. Before this, five malformed shapes raised
a RAW AttributeError straight out of `load_state`, and an invalid MAC survived
the load only to explode much later as a raw ValueError from `bytes.fromhex`
during chunk verification.

Policy: an untrustworthy state file is quarantined byte-for-byte and the
transfer restarts fresh - the same outcome `auto_resume = false` produces.
"""

from __future__ import annotations

import json
import multiprocessing as mp

import pytest

from megabasterd_cli.core.state import (
    StateCorruptionError,
    TransferState,
    clear_state,
    load_state,
    save_state,
    state_path_for,
    validate_state_dict,
)

MAC = "aa" * 16  # 16-byte CBC-MAC, hex-encoded


def _valid(**overrides) -> dict:
    doc = {
        "transfer_type": "download",
        "source": "https://mega.nz/file/ID#<key>",
        "destination": "/tmp/out.bin",
        "total_size": 1024,
        "format_version": 1,
        "completed_chunks": [0, 1],
        "chunk_macs": {"0": MAC, "1": MAC},
        "metadata": {},
    }
    doc.update(overrides)
    return doc


def _write(tmp_path, payload, raw: bool = False):
    destination = tmp_path / "out.bin"
    path = state_path_for(destination)
    path.write_text(payload if raw else json.dumps(payload), encoding="utf-8")
    return destination, path


BAD_ROOTS = {
    "null-root": "null",
    "list-root": "[1, 2, 3]",
    "string-root": '"hello"',
    "number-root": "42",
    "bool-root": "true",
    "not-json": "{{{ broken",
    "not-utf8": None,  # written as raw bytes below
}


@pytest.mark.parametrize("payload", list(BAD_ROOTS.values()), ids=list(BAD_ROOTS))
def test_bad_roots_return_none_without_raising(tmp_path, payload):
    destination = tmp_path / "out.bin"
    path = state_path_for(destination)
    if payload is None:
        path.write_bytes(b"\xff\xfe not utf-8")
    else:
        path.write_text(payload, encoding="utf-8")
    original = path.read_bytes()

    assert load_state(destination) is None  # must not raise
    backups = list(tmp_path.glob("out.bin.mbstate.corrupt.*"))
    assert len(backups) == 1, "the corrupt state must be quarantined"
    assert backups[0].read_bytes() == original, "quarantined byte-for-byte"


BAD_DOCS = {
    "macs-as-list": _valid(chunk_macs=[]),
    "macs-as-string": _valid(chunk_macs="aabb"),
    "invalid-hex": _valid(completed_chunks=[0], chunk_macs={"0": "zz" * 16}),
    "odd-length-hex": _valid(completed_chunks=[0], chunk_macs={"0": "abc"}),
    "short-mac": _valid(completed_chunks=[0], chunk_macs={"0": "aabb"}),
    "long-mac": _valid(completed_chunks=[0], chunk_macs={"0": "aa" * 32}),
    "mac-not-a-string": _valid(completed_chunks=[0], chunk_macs={"0": 1234}),
    "mac-key-not-int": _valid(chunk_macs={"zero": MAC}),
    "mac-key-negative": _valid(chunk_macs={"-1": MAC}),
    "orphan-mac": _valid(completed_chunks=[0], chunk_macs={"0": MAC, "7": MAC}),
    "bool-chunk": _valid(completed_chunks=[True], chunk_macs={}),
    "negative-chunk": _valid(completed_chunks=[-5], chunk_macs={}),
    "duplicate-chunks": _valid(completed_chunks=[0, 0], chunk_macs={"0": MAC}),
    "string-chunk": _valid(completed_chunks=["0"], chunk_macs={}),
    "float-chunk": _valid(completed_chunks=[1.5], chunk_macs={}),
    "chunks-not-a-list": _valid(completed_chunks={"0": 1}, chunk_macs={}),
    "metadata-list": _valid(metadata=[]),
    "metadata-string": _valid(metadata="nope"),
    "negative-size": _valid(total_size=-1),
    "bool-size": _valid(total_size=True),
    "string-size": _valid(total_size="1024"),
    "missing-size": {k: v for k, v in _valid().items() if k != "total_size"},
    "unknown-transfer-type": _valid(transfer_type="teleport"),
    "missing-source": {k: v for k, v in _valid().items() if k != "source"},
    "source-not-a-string": _valid(source=123),
    "destination-not-a-string": _valid(destination=None),
    "bool-format-version": _valid(format_version=True),
}


@pytest.mark.parametrize("doc", list(BAD_DOCS.values()), ids=list(BAD_DOCS))
def test_semantically_invalid_state_is_rejected_and_quarantined(tmp_path, doc):
    destination, path = _write(tmp_path, doc)
    original = path.read_bytes()

    assert load_state(destination) is None
    assert len(list(tmp_path.glob("out.bin.mbstate.corrupt.*"))) == 1
    assert original in {b.read_bytes() for b in tmp_path.glob("out.bin.mbstate.corrupt.*")}


@pytest.mark.parametrize("doc", list(BAD_DOCS.values()), ids=list(BAD_DOCS))
def test_validator_raises_only_state_corruption_error(doc):
    with pytest.raises(StateCorruptionError):
        validate_state_dict(doc)


def test_valid_state_still_loads_and_macs_decode(tmp_path):
    destination, _ = _write(tmp_path, _valid())
    state = load_state(destination)
    assert state is not None
    assert state.completed_chunks == [0, 1]
    assert state.get_chunk_mac(0) == bytes.fromhex(MAC)
    assert not list(tmp_path.glob("out.bin.mbstate.corrupt.*")), "valid state is not quarantined"


def test_no_completed_chunks_is_valid(tmp_path):
    destination, _ = _write(tmp_path, _valid(completed_chunks=[], chunk_macs={}))
    state = load_state(destination)
    assert state is not None and state.completed_chunks == []


def test_get_chunk_mac_never_raises_after_a_successful_load(tmp_path):
    """The old failure mode: load succeeded, verification blew up later."""
    destination, _ = _write(tmp_path, _valid(completed_chunks=[0], chunk_macs={"0": "zz" * 16}))
    state = load_state(destination)
    assert state is None, "an unusable MAC must be rejected at load time"


def test_unsupported_version_is_ignored_not_quarantined(tmp_path):
    destination, _ = _write(tmp_path, _valid(format_version=99))
    assert load_state(destination) is None
    assert not list(tmp_path.glob("out.bin.mbstate.corrupt.*")), "a future version is not corrupt"


def test_round_trip_survives_save_and_load(tmp_path):
    # A download that has committed chunks always has a destination file:
    # the state vouches for those bytes. Creating it keeps the fixture
    # faithful rather than relaxing the durability rule to suit it.
    destination = tmp_path / "out.bin"
    destination.write_bytes(bytes(2048))
    state = TransferState(
        transfer_type="download",
        source="https://mega.nz/file/ID#<key>",
        destination=str(destination),
        total_size=2048,
    )
    state.mark_chunk_done(0, bytes.fromhex(MAC))
    save_state(state)
    reloaded = load_state(destination)
    assert reloaded is not None
    assert reloaded.completed_chunks == [0]
    assert reloaded.get_chunk_mac(0) == bytes.fromhex(MAC)


def test_clear_state_removes_the_state_and_keeps_only_the_lock_sidecar(tmp_path):
    """The `.lock` sidecar is deliberately kept; nothing else may remain.

    This test previously demanded the sidecar be unlinked too. That is the
    unsound tidier option: between `release()` and `unlink()` another process
    can lock the still-open inode while the unlink frees the NAME, so a third
    process locks a FRESH inode and two owners each believe they are exclusive
    - the identical race `utils/helpers.release_destination` documents at
    length for `.mbclaim`. An empty sidecar is inert and is reused.
    """
    destination = tmp_path / "out.bin"
    state = TransferState(
        transfer_type="download", source="u", destination=str(destination), total_size=1
    )
    save_state(state)
    clear_state(destination)
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "out.bin"]
    assert leftovers == ["out.bin.mbstate.lock"], f"unexpected artifacts remain: {leftovers}"


def test_no_temp_files_are_left_after_saving(tmp_path):
    destination = tmp_path / "out.bin"
    state = TransferState(
        transfer_type="upload", source="local", destination=str(destination), total_size=5
    )
    for index in range(5):
        state.mark_chunk_done(index, bytes.fromhex(MAC))
        save_state(state)
    assert not list(tmp_path.glob("*.tmp"))


# ---------------------------------------------------------------------------
# Cross-process safety: a process-local threading.Lock cannot serialize two
# independent CLI processes writing the same .mbstate.
# ---------------------------------------------------------------------------


def _hammer(args):
    """Worker PROCESS: repeatedly rewrite the same state file."""
    destination, chunk_base, rounds = args
    from megabasterd_cli.core.state import TransferState as WorkerState
    from megabasterd_cli.core.state import save_state as save

    state = WorkerState(
        transfer_type="download",
        source="https://mega.nz/file/ID#<key>",
        destination=destination,
        total_size=1_000_000,
    )
    for i in range(rounds):
        state.mark_chunk_done(chunk_base + i, bytes.fromhex("bb" * 16))
        save(state)
    return True


def test_concurrent_processes_never_leave_unreadable_state(tmp_path):
    # A download that has committed chunks always has a destination file:
    # the state vouches for those bytes. Creating it keeps the fixture
    # faithful rather than relaxing the durability rule to suit it.
    destination = str(tmp_path / "out.bin")
    (tmp_path / "out.bin").write_bytes(bytes(4096))
    ctx = mp.get_context("spawn")  # Windows-compatible start method
    with ctx.Pool(4) as pool:
        results = pool.map(_hammer, [(destination, base, 12) for base in (0, 100, 200, 300)])
    assert all(results)

    # Whatever interleaving happened, the file must still parse and validate:
    # a torn write would surface as corruption here.
    state = load_state(tmp_path / "out.bin")
    assert state is not None, "concurrent writers corrupted the state file"
    assert state.completed_chunks, "a committed chunk set must survive"
    assert not list(tmp_path.glob("out.bin.mbstate.corrupt.*")), "no corruption was quarantined"
    assert not list(tmp_path.glob("*.tmp")), "no temp files may be left behind"
