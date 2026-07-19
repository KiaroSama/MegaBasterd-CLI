"""Queue job model and enums.

One `QueueItem` is one download or upload job. The dataclass is the on-disk
shape; `QueueManager` owns serialization, leasing and persistence.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum


class JobStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    DONE = "done"
    FAILED = "failed"
    CANCELED = "canceled"
    # A previous run crashed/was killed while this job was active. Interrupted
    # jobs are re-run automatically; failed jobs need an explicit retry.
    INTERRUPTED = "interrupted"


# An active job whose owner has not heartbeated for this long is considered
# abandoned (crash, reboot, kill) and is safely recovered on the next run.
LEASE_SECONDS = 300


class JobType(str, Enum):
    DOWNLOAD = "download"
    UPLOAD = "upload"


# Statuses that own a finish time. `update_status` writes `finished_iso` for
# exactly these.
_TERMINAL_STATUSES = frozenset(
    {JobStatus.DONE.value, JobStatus.FAILED.value, JobStatus.CANCELED.value}
)


@dataclass
class QueueItem:
    id: str
    type: str  # JobType
    source: str  # URL for downloads, file path for uploads
    destination: str
    size: int = 0
    status: str = JobStatus.PENDING.value
    error: str | None = None
    account: str | None = None
    # Link password for password-protected downloads. Kept in memory in clear
    # for use by the runner, but never serialized in clear (see QueueManager).
    password: str | None = field(default=None, repr=False)
    created_iso: str = ""
    finished_iso: str | None = None
    # Lease/ownership of an active job: which run owns it and when it last
    # proved it was alive. Absent in legacy queue files (safe default None).
    run_id: str | None = None
    heartbeat_iso: str | None = None
    # Lease generation: incremented on every (re)claim and NEVER reset, so a
    # run that lost its lease can be told apart from the current owner even if
    # a run_id repeats. Absent in legacy files (safe default 0).
    lease_epoch: int = 0

    def __post_init__(self) -> None:
        # Fields written by a NEWER version, carried through untouched so a
        # round trip never silently drops them. Not persisted as a field
        # itself: `QueueManager._serialize` re-emits the contents.
        self._extra: dict = {}
        self._enc_password: str | None = None

    @staticmethod
    def new_id() -> str:
        return uuid.uuid4().hex[:12]
