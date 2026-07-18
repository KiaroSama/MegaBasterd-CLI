"""Atomic destination reservation for parallel transfers.

Historical bug: `ensure_unique_path()` used a non-atomic existence check, so
parallel links with identical (or sanitization/truncation-colliding) names
could select the same destination file and the same resume-state file.
"""

from __future__ import annotations

import threading

from megabasterd_cli.utils.helpers import (
    claim_destination,
    release_destination,
    sanitize_filename,
)


def test_parallel_identical_names_get_distinct_destinations(tmp_path):
    target = tmp_path / "video.mp4"
    barrier = threading.Barrier(8)
    claimed: list = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        path = claim_destination(target)
        with lock:
            claimed.append(path)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
        assert not t.is_alive()

    try:
        assert len({str(p) for p in claimed}) == 8, "every transfer needs its own path"
        assert target in claimed
    finally:
        for p in claimed:
            release_destination(p)


def test_sanitized_collisions_get_distinct_destinations(tmp_path):
    # Two different remote names that sanitize to the same local component.
    names = ["report?.txt", "report*.txt"]
    claimed = [claim_destination(tmp_path / sanitize_filename(n)) for n in names]
    try:
        assert claimed[0] != claimed[1]
    finally:
        for p in claimed:
            release_destination(p)


def test_existing_file_is_preserved(tmp_path):
    existing = tmp_path / "keep.bin"
    existing.write_bytes(b"precious")
    claimed = claim_destination(existing)
    try:
        assert claimed != existing
        assert existing.read_bytes() == b"precious"
    finally:
        release_destination(claimed)


def test_overwrite_is_explicit(tmp_path):
    existing = tmp_path / "keep.bin"
    existing.write_bytes(b"precious")
    claimed = claim_destination(existing, overwrite=True)
    try:
        assert claimed == existing
    finally:
        release_destination(claimed)


def test_resumable_existing_destination_is_reused_only_on_match(tmp_path):
    existing = tmp_path / "partial.bin"
    existing.write_bytes(b"\x00" * 10)

    matches = claim_destination(existing, is_resumable=lambda p: True)
    release_destination(matches)
    assert matches == existing

    no_match = claim_destination(existing, is_resumable=lambda p: False)
    release_destination(no_match)
    assert no_match != existing


def test_release_allows_reclaim(tmp_path):
    target = tmp_path / "file.bin"
    first = claim_destination(target)
    assert claim_destination(target) != first  # still held
    release_destination(first)
    release_destination(target.parent / "file (1).bin")
    again = claim_destination(target)
    release_destination(again)
    assert again == target


# ---------------------------------------------------------------------------
# Cross-process reservation.
#
# A threading.Lock and a process-local set cannot see another OS process, so
# two `mb` runs used to pick the SAME destination and write over each other.
# ---------------------------------------------------------------------------

import multiprocessing as mp  # noqa: E402
import os as _os  # noqa: E402
from pathlib import Path as FsPath  # noqa: E402

from megabasterd_cli.utils.helpers import CLAIM_SUFFIX  # noqa: E402


def _claim_in_process(args):
    """Worker PROCESS: wait on the barrier, then claim the same target."""
    directory, name, ready_dir, worker_count = args
    import time
    from pathlib import Path as FsPath

    from megabasterd_cli.utils.helpers import claim_destination as claim

    # Rendezvous through the filesystem (a mp.Barrier cannot cross `spawn`
    # cleanly on Windows): announce readiness, then wait for everyone.
    FsPath(ready_dir, f"{_os.getpid()}.ready").write_text("1", encoding="utf-8")
    deadline = time.monotonic() + 30
    while len(list(FsPath(ready_dir).glob("*.ready"))) < worker_count:
        if time.monotonic() > deadline:
            break
        time.sleep(0.01)

    claimed = claim(FsPath(directory) / name)
    # Hold the reservation while the others are still claiming, exactly as a
    # real transfer would, then prove we can create the file uncontested.
    FsPath(claimed).write_text(str(_os.getpid()), encoding="utf-8")
    time.sleep(0.4)
    return str(claimed)


def test_two_processes_cannot_claim_the_same_destination(tmp_path):
    ready = tmp_path / "ready"
    ready.mkdir()
    workers = 4
    ctx = mp.get_context("spawn")  # Windows-compatible
    args = [(str(tmp_path), "shared.bin", str(ready), workers)] * workers
    with ctx.Pool(workers) as pool:
        claimed = pool.map(_claim_in_process, args)

    assert len(claimed) == workers
    assert len(set(claimed)) == workers, f"two processes claimed the same path: {claimed}"
    # Each process wrote its own pid into its own file: nothing was overwritten.
    contents = [FsPath(p).read_text(encoding="utf-8") for p in claimed]
    assert len(set(contents)) == workers


def _crash_after_claiming(args):
    """Worker PROCESS: claim, then die WITHOUT releasing."""
    directory, name = args
    from pathlib import Path as FsPath

    from megabasterd_cli.utils.helpers import claim_destination as claim

    claimed = claim(FsPath(directory) / name)
    _os._exit(1)  # hard exit: no cleanup, no release
    return str(claimed)  # pragma: no cover


def test_a_crashed_owner_does_not_block_the_destination_forever(tmp_path):
    """The OS drops an advisory lock when the holder dies, so there is no
    stale reservation to recover from."""
    ctx = mp.get_context("spawn")
    proc = ctx.Process(target=_crash_after_claiming, args=((str(tmp_path), "solo.bin"),))
    proc.start()
    proc.join(timeout=60)
    assert proc.exitcode == 1, "the worker must have crashed without releasing"

    # The very same path must be claimable again by this process.
    reclaimed = claim_destination(tmp_path / "solo.bin")
    try:
        assert reclaimed == tmp_path / "solo.bin", f"stale reservation blocked it: {reclaimed}"
    finally:
        release_destination(reclaimed)


def test_release_removes_the_claim_sidecar(tmp_path):
    target = tmp_path / "clean.bin"
    claimed = claim_destination(target)
    release_destination(claimed)
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.endswith(CLAIM_SUFFIX)]
    assert leftovers == [], f"claim sidecars must not leak: {leftovers}"


def test_successful_transfer_leaves_no_reservation_artifacts(tmp_path):
    for _ in range(3):
        claimed = claim_destination(tmp_path / "cycle.bin")
        claimed.write_text("done", encoding="utf-8")
        release_destination(claimed)
    names = sorted(p.name for p in tmp_path.iterdir())
    assert names == ["cycle.bin", "cycle (1).bin", "cycle (2).bin"] or all(
        not n.endswith(CLAIM_SUFFIX) for n in names
    ), names
