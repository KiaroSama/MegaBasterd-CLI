"""QueueManager thread/process safety and atomic claiming (Mandatory Fix 2).

Historical bugs: no mutation lock, a fixed `queue.json.tmp` shared by all
savers, heartbeat/main-thread save races, and a `runnable()` +
`mark_active()` window that let two runs execute the same job.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading

import pytest

from megabasterd_cli.queue.manager import (
    JobStatus,
    QueueLockError,
    QueueManager,
)
from megabasterd_cli.utils.filelock import FileLock
from tests.queue_helpers import add as _add


def _mgr(tmp_path, **kwargs) -> QueueManager:
    return QueueManager(tmp_path / "queue.json", **kwargs)


def test_threads_racing_touch_and_update_status_do_not_corrupt(tmp_path):
    q = _mgr(tmp_path)
    item = _add(q)
    q.mark_active(item.id, "run-1")
    stop = threading.Event()
    errors: list[BaseException] = []

    def toucher() -> None:
        try:
            while not stop.is_set():
                q.touch(item.id, "run-1")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=toucher, daemon=True) for _ in range(3)]
    for t in threads:
        t.start()
    for _ in range(10):
        q.update_status(item.id, JobStatus.ACTIVE)
    q.update_status(item.id, JobStatus.DONE)
    stop.set()
    for t in threads:
        t.join(timeout=10)
        assert not t.is_alive()
    assert not errors, f"concurrent mutation raised: {errors[:1]}"

    fresh = _mgr(tmp_path)
    assert fresh.items[0].status == JobStatus.DONE.value
    # File stayed parseable JSON throughout.
    json.loads((tmp_path / "queue.json").read_text(encoding="utf-8"))


def test_two_managers_in_one_process_cannot_claim_same_job(tmp_path):
    q1 = _mgr(tmp_path)
    _add(q1)
    q2 = _mgr(tmp_path)

    first = q1.claim_next("run-1")
    second = q2.claim_next("run-2")
    assert first is not None
    assert second is None, "a live lease must not be claimable by another manager"


def test_two_managers_claim_distinct_jobs(tmp_path):
    q1 = _mgr(tmp_path)
    a = _add(q1)
    b = _add(q1)
    q2 = _mgr(tmp_path)
    got1 = q1.claim_next("run-1")
    got2 = q2.claim_next("run-2")
    assert {got1.id, got2.id} == {a.id, b.id}


_SUBPROCESS_CLAIM = r"""
import sys
from pathlib import Path
from megabasterd_cli.queue.manager import QueueManager

q = QueueManager(Path(sys.argv[1]) / "queue.json")
item = q.claim_next(sys.argv[2])
print(item.id if item is not None else "NONE")
"""


def test_two_subprocesses_racing_produce_exactly_one_winner(tmp_path):
    q = _mgr(tmp_path)
    _add(q)

    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _SUBPROCESS_CLAIM, str(tmp_path), f"run-{i}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for i in range(2)
    ]
    outputs = []
    for p in procs:
        out, err = p.communicate(timeout=60)
        assert p.returncode == 0, err
        outputs.append(out.strip())
    winners = [o for o in outputs if o != "NONE"]
    assert len(winners) == 1, f"exactly one process may win the claim, got {outputs}"


def test_concurrent_saves_use_unique_temp_files(tmp_path):
    q = _mgr(tmp_path)
    items = [_add(q) for _ in range(4)]
    errors: list[BaseException] = []

    def mutate(item_id: str) -> None:
        try:
            for _ in range(15):
                q.touch(item_id, "nobody")  # reload+save churn
                q.update_status(item_id, JobStatus.PENDING)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=mutate, args=(i.id,), daemon=True) for i in items]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
        assert not t.is_alive()
    assert not errors
    data = json.loads((tmp_path / "queue.json").read_text(encoding="utf-8"))
    assert len(data) == 4
    leftovers = list(tmp_path.glob("queue.json.*.tmp"))
    assert leftovers == [], "temp files must be consumed by os.replace"


def test_heartbeat_cannot_revert_terminal_status(tmp_path):
    q1 = _mgr(tmp_path)
    item = _add(q1)
    q1.mark_active(item.id, "run-1")
    # Another process/instance finishes the job.
    q2 = _mgr(tmp_path)
    q2.update_status(item.id, JobStatus.DONE)
    # The stale owner heartbeats afterwards: must be a no-op.
    q1.touch(item.id, "run-1")
    fresh = _mgr(tmp_path)
    assert fresh.items[0].status == JobStatus.DONE.value
    assert fresh.items[0].heartbeat_iso is None


def test_stale_writer_cannot_overwrite_newer_status_of_other_items(tmp_path):
    q1 = _mgr(tmp_path)
    x = _add(q1)
    y = _add(q1)
    # q1 holds an old in-memory snapshot (both pending); q2 finishes Y.
    q2 = _mgr(tmp_path)
    q2.update_status(y.id, JobStatus.DONE)
    # q1 mutates X; its write must NOT resurrect Y's old pending state.
    q1.update_status(x.id, JobStatus.FAILED, error="boom")
    fresh = _mgr(tmp_path)
    statuses = {i.id: i.status for i in fresh.items}
    assert statuses[x.id] == JobStatus.FAILED.value
    assert statuses[y.id] == JobStatus.DONE.value


def test_secrets_survive_claim_heartbeat_failure_retry_reload(tmp_path):
    q = _mgr(tmp_path)
    item = _add(q, password="link-secret")
    claimed = q.claim_next("run-1")
    assert claimed.id == item.id
    q.touch(item.id, "run-1")
    q.update_status(item.id, JobStatus.FAILED, error="boom")
    assert q.retry(item.id) is True
    fresh = _mgr(tmp_path)
    assert fresh.items[0].password == "link-secret"
    raw = json.loads((tmp_path / "queue.json").read_text(encoding="utf-8"))
    assert "password" not in raw[0], "plaintext must never be persisted"
    assert raw[0].get("enc_password")


def test_lock_timeout_raises_clear_domain_error(tmp_path):
    q = _mgr(tmp_path, lock_timeout=0.3)
    _add(q)
    blocker = FileLock(tmp_path / "queue.json.lock")
    blocker.acquire(timeout=5)
    try:
        with pytest.raises(QueueLockError, match="Could not lock the transfer queue"):
            q.claim_next("run-1")
    finally:
        blocker.release()
    # Lock released: the same operation now succeeds.
    assert q.claim_next("run-1") is not None


def test_queue_run_lock_timeout_exits_nonzero(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from megabasterd_cli.cli import cli

    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))
    runner = CliRunner()
    add = runner.invoke(
        cli, ["-q", "queue", "add-download", "https://mega.nz/file/a#b", "-o", str(tmp_path)]
    )
    assert add.exit_code == 0

    def locked_claim(self, run_id, lease_seconds=300):
        raise QueueLockError("Could not lock the transfer queue within 10s")

    monkeypatch.setattr(QueueManager, "claim_next", locked_claim)
    result = runner.invoke(cli, ["-q", "queue", "run"])
    assert result.exit_code == 1
