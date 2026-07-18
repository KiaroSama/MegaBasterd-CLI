"""Every distinct corruption episode is preserved at least once.

Both stores used to skip the backup whenever ANY older `.corrupt.*` file
existed, so this sequence silently destroyed data:

    corrupt A -> recover (A backed up) -> corrupt B -> recover (B LOST)

Backups are now deduplicated by content hash, so repeated reads of the same
corrupt file still produce exactly one backup while a genuinely different
corruption always gets its own.
"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import stat

import pytest

from megabasterd_cli.config import ConfigStore
from megabasterd_cli.queue.manager import QueueManager
from megabasterd_cli.utils.corruption import content_digest, preserve_corrupt_file

CORRUPT_A = b'{"episode": "A",,,'
CORRUPT_B = b"[not even the same shape"


def _backups(tmp_path, name):
    return sorted(tmp_path.glob(f"{name}.corrupt.*"))


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_config_two_distinct_episodes_produce_two_backups(tmp_path):
    path = tmp_path / "config.json"

    path.write_bytes(CORRUPT_A)
    first = ConfigStore(path=path, lock_timeout=0.5).recover()
    path.write_bytes(CORRUPT_B)
    second = ConfigStore(path=path, lock_timeout=0.5).recover()

    backups = _backups(tmp_path, "config.json")
    assert len(backups) == 2, f"both episodes must be preserved, got {backups}"
    contents = {b.read_bytes() for b in backups}
    assert contents == {CORRUPT_A, CORRUPT_B}
    assert first is not None and first.read_bytes() == CORRUPT_A
    assert second is not None and second.read_bytes() == CORRUPT_B
    assert first != second, "recovery must report THIS episode's backup"


def test_config_repeated_reads_of_one_episode_do_not_pile_up(tmp_path):
    path = tmp_path / "config.json"
    path.write_bytes(CORRUPT_A)
    for _ in range(6):
        ConfigStore(path=path, lock_timeout=0.5).load()
    assert len(_backups(tmp_path, "config.json")) == 1


def test_config_backup_reported_is_the_current_episode(tmp_path):
    path = tmp_path / "config.json"
    path.write_bytes(CORRUPT_A)
    ConfigStore(path=path, lock_timeout=0.5).recover()  # leaves an older backup
    path.write_bytes(CORRUPT_B)
    store = ConfigStore(path=path, lock_timeout=0.5)
    store.load()
    assert store.corrupt_backup is not None
    assert store.corrupt_backup.read_bytes() == CORRUPT_B


# ---------------------------------------------------------------------------
# Queue
# ---------------------------------------------------------------------------


def test_queue_two_distinct_episodes_produce_two_backups(tmp_path):
    path = tmp_path / "queue.json"

    path.write_bytes(CORRUPT_A)
    QueueManager(path=path, lock_timeout=0.5).reset()
    path.write_bytes(CORRUPT_B)
    mgr = QueueManager(path=path, lock_timeout=0.5)
    assert mgr.corrupt_backup is not None
    assert mgr.corrupt_backup.read_bytes() == CORRUPT_B
    mgr.reset()

    backups = _backups(tmp_path, "queue.json")
    assert len(backups) == 2
    assert {b.read_bytes() for b in backups} == {CORRUPT_A, CORRUPT_B}


def test_queue_repeated_loads_of_one_episode_do_not_pile_up(tmp_path):
    path = tmp_path / "queue.json"
    path.write_bytes(CORRUPT_A)
    for _ in range(6):
        QueueManager(path=path, lock_timeout=0.5)
    assert len(_backups(tmp_path, "queue.json")) == 1


# ---------------------------------------------------------------------------
# Failure reporting and collisions
# ---------------------------------------------------------------------------


def test_backup_write_failure_is_reported_and_original_kept(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    path.write_bytes(CORRUPT_A)

    real_open = os.open

    def refuse(target, *args, **kwargs):
        # Only the backup write fails; the file lock must keep working.
        if ".corrupt." in str(target):
            raise OSError("read-only filesystem")
        return real_open(target, *args, **kwargs)

    monkeypatch.setattr(os, "open", refuse)
    store = ConfigStore(path=path, lock_timeout=0.5)
    store.load()
    assert store.is_corrupt
    assert store.corrupt_backup is None, "no backup path may be claimed"
    assert "could NOT be written" in store.corruption_reason
    monkeypatch.undo()
    assert path.read_bytes() == CORRUPT_A


def test_filename_collision_still_preserves_the_content(tmp_path):
    """A pre-existing file on the computed name must not swallow the episode."""
    path = tmp_path / "queue.json"
    path.write_bytes(CORRUPT_A)
    digest = content_digest(CORRUPT_A)
    # Squat every plain name for this digest with UNRELATED content.
    import time as _time

    stamp = _time.strftime("%Y%m%d-%H%M%S", _time.gmtime())
    squatter = tmp_path / f"queue.json.corrupt.{stamp}-{digest}.json"
    squatter.write_bytes(b"unrelated squatter content")

    result = preserve_corrupt_file(path, CORRUPT_A)
    assert result is not None
    assert result != squatter
    assert result.read_bytes() == CORRUPT_A


def test_identical_content_is_adopted_not_duplicated(tmp_path):
    path = tmp_path / "queue.json"
    path.write_bytes(CORRUPT_A)
    first = preserve_corrupt_file(path, CORRUPT_A)
    second = preserve_corrupt_file(path, CORRUPT_A)
    assert first == second
    assert len(_backups(tmp_path, "queue.json")) == 1


def _detect(args):
    """Worker: a separate PROCESS detecting the same corruption."""
    directory, name = args
    from pathlib import Path

    from megabasterd_cli.config import ConfigStore as Store

    store = Store(path=Path(directory) / name, lock_timeout=10.0)
    store.load()
    return store.is_corrupt


@pytest.mark.skipif(
    mp.get_start_method(allow_none=True) not in (None, "spawn", "fork"),
    reason="unsupported start method",
)
def test_concurrent_processes_preserve_exactly_one_backup(tmp_path):
    path = tmp_path / "config.json"
    path.write_bytes(CORRUPT_A)
    ctx = mp.get_context("spawn")  # Windows-compatible
    with ctx.Pool(4) as pool:
        results = pool.map(_detect, [(str(tmp_path), "config.json")] * 4)
    assert all(results), "every process must see the corruption"
    backups = _backups(tmp_path, "config.json")
    assert len(backups) == 1, f"exactly one backup for one content, got {backups}"
    assert backups[0].read_bytes() == CORRUPT_A
    assert path.read_bytes() == CORRUPT_A


def test_recovered_config_is_valid_json_after_two_episodes(tmp_path):
    path = tmp_path / "config.json"
    path.write_bytes(CORRUPT_A)
    ConfigStore(path=path, lock_timeout=0.5).recover()
    path.write_bytes(CORRUPT_B)
    ConfigStore(path=path, lock_timeout=0.5).recover()
    assert json.loads(path.read_text(encoding="utf-8"))["max_workers"] == 8


def test_backup_permissions_are_not_widened(tmp_path):
    """The backup may hold secrets; it must not be world-readable on POSIX."""
    if os.name == "nt":
        pytest.skip("POSIX mode bits only")
    path = tmp_path / "queue.json"
    path.write_bytes(CORRUPT_A)
    backup = preserve_corrupt_file(path, CORRUPT_A)
    assert backup is not None
    mode = stat.S_IMODE(backup.stat().st_mode)
    assert not mode & stat.S_IROTH, f"backup is world-readable: {oct(mode)}"
