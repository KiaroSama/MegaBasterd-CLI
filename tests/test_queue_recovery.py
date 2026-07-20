"""Interrupted-queue recovery: leases, heartbeats, retry, migration.

Historical bug: jobs were marked `active` before the transfer, but
`pending()` ignored non-pending statuses forever, so a crash/reboot orphaned
the job permanently.
"""

from __future__ import annotations

import datetime as dt
import json

from megabasterd_cli.queue.manager import JobStatus, QueueManager
from tests.queue_helpers import add as _add


def _mgr(tmp_path) -> QueueManager:
    return QueueManager(tmp_path / "queue.json")


def test_simulated_crash_is_recovered_by_next_run(tmp_path):
    q = _mgr(tmp_path)
    item = _add(q)
    q.mark_active(item.id, run_id="run-1")
    # Simulate the crash: no further heartbeats; a new run starts much later.
    stale = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat()
    q.items[0].heartbeat_iso = stale
    q.save()

    q2 = _mgr(tmp_path)
    recovered = q2.recover_interrupted()
    assert [i.id for i in recovered] == [item.id]
    assert q2.items[0].status == JobStatus.INTERRUPTED.value
    assert [i.id for i in q2.runnable()] == [item.id]


def test_live_lease_is_not_stolen(tmp_path):
    q = _mgr(tmp_path)
    item = _add(q)
    q.mark_active(item.id, run_id="run-1")  # fresh heartbeat

    q2 = _mgr(tmp_path)
    assert q2.recover_interrupted() == []
    assert q2.items[0].status == JobStatus.ACTIVE.value
    assert q2.runnable() == []


def test_heartbeat_touch_refreshes_only_owned_jobs(tmp_path):
    q = _mgr(tmp_path)
    item = _add(q)
    q.mark_active(item.id, run_id="run-1")
    before = q.items[0].heartbeat_iso
    q.touch(item.id, "someone-else")  # not the owner: no refresh
    assert q.items[0].heartbeat_iso == before
    q.touch(item.id, "run-1")
    assert q.items[0].heartbeat_iso >= before


def test_failed_and_interrupted_remain_distinct(tmp_path):
    q = _mgr(tmp_path)
    failed = _add(q)
    interrupted = _add(q)
    q.update_status(failed.id, JobStatus.FAILED, error="boom")
    q.mark_active(interrupted.id, run_id="dead-run")
    q.items[1].heartbeat_iso = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)
    ).isoformat()
    q.save()

    q2 = _mgr(tmp_path)
    q2.recover_interrupted()
    statuses = {i.id: i.status for i in q2.items}
    assert statuses[failed.id] == JobStatus.FAILED.value, "failed jobs are not auto-retried"
    assert statuses[interrupted.id] == JobStatus.INTERRUPTED.value
    # Only the interrupted one is runnable without an explicit retry.
    assert [i.id for i in q2.runnable()] == [interrupted.id]


def test_retry_preserves_secrets_and_resets_status(tmp_path):
    q = _mgr(tmp_path)
    item = _add(q, password="link-secret")
    q.update_status(item.id, JobStatus.FAILED, error="boom")

    q2 = _mgr(tmp_path)
    assert q2.retry(item.id) is True
    entry = q2.items[0]
    assert entry.status == JobStatus.PENDING.value
    assert entry.error is None
    assert entry.password == "link-secret", "encrypted queue secret must survive retry"
    # DONE jobs are not retryable.
    q2.update_status(item.id, JobStatus.DONE)
    assert q2.retry(item.id) is False


def test_legacy_queue_json_migrates_safely(tmp_path):
    path = tmp_path / "queue.json"
    legacy = [
        {
            "id": "legacy1",
            "type": "download",
            "source": "https://mega.nz/file/a#b",
            "destination": "",
            "size": 0,
            "status": "active",  # left behind by an old crashed run
            "error": None,
            "account": None,
            "created_iso": "2026-01-01T00:00:00+00:00",
            "finished_iso": None,
        }
    ]
    path.write_text(json.dumps(legacy), encoding="utf-8")

    q = QueueManager(path)
    assert q.items[0].run_id is None
    recovered = q.recover_interrupted()
    assert [i.id for i in recovered] == ["legacy1"], "legacy active jobs must be recovered"
    assert q.runnable()[0].id == "legacy1"
