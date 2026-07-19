"""Exceptions raised by the persistent transfer queue."""

from __future__ import annotations


class QueueLockError(Exception):
    """Raised when the cross-process queue lock cannot be acquired in time."""


class QueueCorruptionError(Exception):
    """Raised when the queue file is malformed or has an invalid schema.

    A corrupt queue is preserved (never overwritten) and mutations are blocked
    until the operator resolves it with `queue reset` or manual recovery.
    """


class QueueOwnershipError(Exception):
    """Raised when a run mutates a job it no longer owns.

    A lease is (run_id, lease_epoch). Once the lease expires and another run
    re-claims the job, the previous owner's DONE/FAILED/INTERRUPTED write must
    be REFUSED - silently applying it would mark a still-running job complete
    or overwrite the new owner's result.
    """


class QueueLeaseLostError(Exception):
    """Raised by a runner that can no longer prove it owns its active job.

    Signals that in-flight work must stop rather than race the new owner.
    """


class QueueKeyError(Exception):
    """Raised when the local queue key file is present but corrupt."""
