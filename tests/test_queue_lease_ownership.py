"""Lease ownership: only the current owner may mutate a leased job (B12).

Historical bug: `run_id` was checked in exactly ONE place (`touch`).
`update_status`/`mark_active` matched on `item.id` alone, so after a lease
expired and a second run re-claimed the job, the FIRST run could still write
DONE/FAILED over the new owner's state - and both runs downloaded the same
job into the same directory.
"""

from __future__ import annotations

import datetime as dt
import json
import threading

import pytest

from megabasterd_cli.queue.manager import (
    JobStatus,
    JobType,
    QueueItem,
    QueueManager,
    QueueOwnershipError,
)

# Every concurrent wait in this module is bounded by this; no sleep-based races.
TIMEOUT = 30.0


def _mgr(tmp_path) -> QueueManager:
    return QueueManager(tmp_path / "queue.json")


def _add(q: QueueManager, **kwargs) -> QueueItem:
    item = QueueItem(
        id=QueueItem.new_id(),
        type=kwargs.pop("type", JobType.DOWNLOAD.value),
        source=kwargs.pop("source", "https://mega.nz/file/x#y"),
        destination=kwargs.pop("destination", ""),
        **kwargs,
    )
    q.add(item)
    return item


def _expire_lease(q: QueueManager, item_id: str) -> None:
    """Push the heartbeat far enough back that the lease is reclaimable."""
    stale = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat()
    for item in q.items:
        if item.id == item_id:
            item.heartbeat_iso = stale
    q.save()


def test_claim_increments_lease_epoch(tmp_path):
    q = _mgr(tmp_path)
    item = _add(q)
    assert item.lease_epoch == 0, "a fresh job carries generation 0"
    first = q.claim_next("run-A")
    assert first.lease_epoch == 1
    _expire_lease(q, item.id)
    second = _mgr(tmp_path).claim_next("run-B")
    assert second.lease_epoch == 2, "every (re)claim starts a new generation"


def test_previous_owner_cannot_mark_reclaimed_job_done(tmp_path):
    """The confirmed B12 scenario: A stalls, B re-leases, A finishes second."""
    q_a = _mgr(tmp_path)
    item = _add(q_a)
    claimed_a = q_a.claim_next("run-A")

    # A's heartbeats die; after LEASE_SECONDS run B re-leases the same job.
    _expire_lease(q_a, item.id)
    q_b = _mgr(tmp_path)
    claimed_b = q_b.claim_next("run-B")
    assert claimed_b is not None and claimed_b.id == item.id

    # B finishes first and legitimately records DONE.
    q_b.update_status(item.id, JobStatus.DONE, run_id="run-B", lease_epoch=claimed_b.lease_epoch)

    # A finishes second and tries to write FAILED over it: must be REFUSED.
    with pytest.raises(QueueOwnershipError):
        q_a.update_status(
            item.id,
            JobStatus.FAILED,
            error="boom",
            run_id="run-A",
            lease_epoch=claimed_a.lease_epoch,
        )
    assert _mgr(tmp_path).items[0].status == JobStatus.DONE.value


def test_previous_owner_cannot_clear_the_new_owners_lease(tmp_path):
    """A's DONE write must not clear B's still-running lease."""
    q_a = _mgr(tmp_path)
    item = _add(q_a)
    claimed_a = q_a.claim_next("run-A")
    _expire_lease(q_a, item.id)
    q_b = _mgr(tmp_path)
    q_b.claim_next("run-B")

    with pytest.raises(QueueOwnershipError):
        q_a.update_status(
            item.id, JobStatus.DONE, run_id="run-A", lease_epoch=claimed_a.lease_epoch
        )
    fresh = _mgr(tmp_path).items[0]
    assert fresh.status == JobStatus.ACTIVE.value
    assert fresh.run_id == "run-B", "the live owner keeps its lease"
    assert fresh.heartbeat_iso is not None


def test_stale_generation_is_refused_even_with_a_matching_run_id(tmp_path):
    """run_id alone is not enough: the generation must match too."""
    q = _mgr(tmp_path)
    item = _add(q)
    stale = q.claim_next("run-A")
    _expire_lease(q, item.id)
    # The SAME run re-claims after recovery: a newer generation invalidates
    # anything still in flight from the previous attempt.
    q.claim_next("run-A")
    with pytest.raises(QueueOwnershipError):
        q.update_status(item.id, JobStatus.DONE, run_id="run-A", lease_epoch=stale.lease_epoch)


def test_interrupt_path_from_a_lost_lease_is_refused(tmp_path):
    """Ctrl-C in the old run must not reset a job another run now owns."""
    q_a = _mgr(tmp_path)
    item = _add(q_a)
    claimed_a = q_a.claim_next("run-A")
    _expire_lease(q_a, item.id)
    q_b = _mgr(tmp_path)
    q_b.claim_next("run-B")

    with pytest.raises(QueueOwnershipError):
        q_a.update_status(
            item.id, JobStatus.INTERRUPTED, run_id="run-A", lease_epoch=claimed_a.lease_epoch
        )
    assert _mgr(tmp_path).items[0].status == JobStatus.ACTIVE.value


def test_current_owner_may_still_write_every_status(tmp_path):
    for status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.INTERRUPTED):
        q = QueueManager(tmp_path / f"queue-{status.value}.json")
        item = _add(q)
        claimed = q.claim_next("run-A")
        q.update_status(item.id, status, error="x", run_id="run-A", lease_epoch=claimed.lease_epoch)
        assert q.items[0].status == status.value
        assert q.items[0].run_id is None, "a finished job releases its lease"


def test_touch_reports_lease_loss_instead_of_failing_silently(tmp_path):
    q_a = _mgr(tmp_path)
    item = _add(q_a)
    claimed = q_a.claim_next("run-A")
    assert q_a.touch(item.id, "run-A", lease_epoch=claimed.lease_epoch) is True

    _expire_lease(q_a, item.id)
    _mgr(tmp_path).claim_next("run-B")
    assert (
        q_a.touch(item.id, "run-A", lease_epoch=claimed.lease_epoch) is False
    ), "a heartbeat from a lost lease must report the loss, not no-op silently"


def test_mark_active_refuses_to_steal_a_live_lease(tmp_path):
    q = _mgr(tmp_path)
    item = _add(q)
    q.claim_next("run-A")
    with pytest.raises(QueueOwnershipError):
        q.mark_active(item.id, "run-B")
    assert q.items[0].run_id == "run-A"
    # An expired lease is fair game again.
    _expire_lease(q, item.id)
    q.mark_active(item.id, "run-B")
    assert q.items[0].run_id == "run-B"


def test_two_threads_racing_completion_and_reclaim_produce_one_writer(tmp_path):
    """Fault injection, not timing: B re-leases while A is parked mid-write."""
    q_a = _mgr(tmp_path)
    item = _add(q_a)
    claimed_a = q_a.claim_next("run-A")
    _expire_lease(q_a, item.id)

    reclaimed = threading.Barrier(2, timeout=TIMEOUT)
    results: dict[str, BaseException | None] = {}

    def reclaim() -> None:
        q_b = _mgr(tmp_path)
        got = q_b.claim_next("run-B")
        q_b.update_status(item.id, JobStatus.DONE, run_id="run-B", lease_epoch=got.lease_epoch)
        reclaimed.wait()

    def finish_late() -> None:
        reclaimed.wait()  # only write AFTER the reclaim landed
        try:
            q_a.update_status(
                item.id, JobStatus.FAILED, run_id="run-A", lease_epoch=claimed_a.lease_epoch
            )
            results["a"] = None
        except BaseException as exc:  # noqa: BLE001
            results["a"] = exc

    threads = [threading.Thread(target=fn, daemon=True) for fn in (reclaim, finish_late)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=TIMEOUT)
        assert not t.is_alive(), "thread did not finish within the hard timeout"

    assert isinstance(results["a"], QueueOwnershipError)
    assert _mgr(tmp_path).items[0].status == JobStatus.DONE.value


def test_legacy_queue_file_without_lease_epoch_still_loads(tmp_path):
    path = tmp_path / "queue.json"
    legacy = [
        {
            "id": "legacy1",
            "type": "download",
            "source": "https://mega.nz/file/a#b",
            "destination": "",
            "size": 0,
            "status": "pending",
            "error": None,
            "account": None,
            "created_iso": "2026-01-01T00:00:00+00:00",
            "finished_iso": None,
        }
    ]
    path.write_text(json.dumps(legacy), encoding="utf-8")

    q = QueueManager(path)
    assert q.items[0].lease_epoch == 0
    claimed = q.claim_next("run-A")
    assert claimed.lease_epoch == 1
    q.update_status("legacy1", JobStatus.DONE, run_id="run-A", lease_epoch=1)
    # The generation survives the round trip so a stale writer stays locked out.
    assert QueueManager(path).items[0].lease_epoch == 1


def test_corrupt_lease_epoch_is_rejected(tmp_path):
    path = tmp_path / "queue.json"
    path.write_text(
        json.dumps(
            [
                {
                    "id": "a",
                    "type": "download",
                    "source": "https://mega.nz/file/a#b",
                    "destination": "",
                    "lease_epoch": -1,
                }
            ]
        ),
        encoding="utf-8",
    )
    assert QueueManager(path).is_corrupt
