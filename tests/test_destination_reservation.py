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
