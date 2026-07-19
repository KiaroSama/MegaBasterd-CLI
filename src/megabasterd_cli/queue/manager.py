"""Persistent transfer queue.

Stores a JSON list of pending/active/failed transfers so the CLI can pick
them up across runs. Each item is one download or upload job.

This module is the queue entry point: the model, the schema validation, the
secret box and the atomic writer live in sibling modules and are re-exported
here so `from ...queue.manager import X` keeps working.
"""

from __future__ import annotations

import contextlib
import json
import logging
import threading
from dataclasses import asdict, fields
from pathlib import Path

from ..utils.corruption import preserve_corrupt_file
from ..utils.filelock import FileLock, FileLockError
from .errors import (
    QueueCorruptionError,
    QueueKeyError,
    QueueLeaseLostError,
    QueueLockError,
    QueueOwnershipError,
)
from .models import (  # noqa: F401 - _TERMINAL_STATUSES/JobType re-exported for compatibility
    _TERMINAL_STATUSES,
    LEASE_SECONDS,
    JobStatus,
    JobType,
    QueueItem,
)
from .schema import (  # noqa: F401 - private validators re-exported for compatibility
    _OPTIONAL_STR_ITEM_FIELDS,
    _REQUIRED_ITEM_FIELDS,
    _validate_iso_timestamp,
    validate_raw_item,
    validate_unique_ids,
)
from .secretbox import (  # noqa: F401 - secret-blob constants re-exported for compatibility
    _QUEUE_KEY_LEN,
    _QUEUE_SECRET_AAD,
    _QUEUE_SECRET_VERSION,
    QueueSecretBox,
)
from .storage import atomic_write_text

log = logging.getLogger(__name__)

__all__ = [
    "LEASE_SECONDS",
    "JobStatus",
    "JobType",
    "QueueCorruptionError",
    "QueueItem",
    "QueueKeyError",
    "QueueLeaseLostError",
    "QueueLockError",
    "QueueManager",
    "QueueOwnershipError",
    "QueueSecretBox",
]


class QueueManager:
    """JSON-file backed transfer queue.

    Locking contract: every read-modify-write mutation runs inside
    `_locked()`, which holds (a) a per-instance re-entrant mutex and (b) the
    cross-process/cross-instance file lock, reloads the newest queue from
    disk, applies the mutation, and persists it. This makes mutations
    last-reader-wins-free: a stale in-memory snapshot can never overwrite a
    newer on-disk status, a heartbeat can never revert a terminal state, and
    two runners (threads, instances, or processes) can never claim one job.
    """

    def __init__(
        self,
        path: Path,
        secret_box: QueueSecretBox | None = None,
        lock_timeout: float = 10.0,
    ):
        self.path = path
        self.secret_box = secret_box or QueueSecretBox(path.parent / "queue.key")
        self.items: list[QueueItem] = []
        self.lock_timeout = lock_timeout
        self._field_names = {f.name for f in fields(QueueItem)}
        self._mutex = threading.RLock()
        self._file_lock = FileLock(
            path.parent / (path.name + ".lock"),
            message=(
                f"Could not lock the transfer queue within {lock_timeout:.0f}s; "
                "another queue operation is holding it. Retry after it finishes."
            ),
        )
        self._lock_depth = 0
        # Set by `_load` when the on-disk queue is malformed/invalid-schema.
        self._corrupt = False
        self._corrupt_reason = ""
        self._corrupt_backup: Path | None = None
        with self._locked():
            self._load()

    @contextlib.contextmanager
    def _locked(self):
        """Hold the instance mutex plus the cross-process file lock (once)."""
        with self._mutex:
            if self._lock_depth == 0:
                try:
                    self._file_lock.acquire(timeout=self.lock_timeout)
                except FileLockError as exc:
                    raise QueueLockError(str(exc)) from None
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
                if self._lock_depth == 0:
                    self._file_lock.release()

    def _ensure_writable(self) -> None:
        """Block mutations while the on-disk queue is corrupt."""
        if self._corrupt:
            raise QueueCorruptionError(self._corrupt_reason)

    def _deserialize(self, raw: dict) -> QueueItem:
        raw = dict(raw)
        enc = raw.pop("enc_password", None)
        legacy_plaintext = raw.pop("password", None)
        item = QueueItem(**{k: v for k, v in raw.items() if k in self._field_names})
        # Forward compatibility: fields written by a NEWER version are carried
        # through untouched instead of being silently dropped on the next save.
        item._extra = {k: v for k, v in raw.items() if k not in self._field_names}  # noqa: SLF001
        # Preserve the raw encrypted token so an unrecoverable secret is never
        # silently dropped when the queue is rewritten.
        item._enc_password = enc
        if enc:
            try:
                item.password = self.secret_box.decrypt(enc)
                item._enc_password = None
            except Exception:  # noqa: BLE001 - never expose the secret/key error
                log.warning(
                    "Could not unlock the stored password for queue item %s; "
                    "it will be required again at run time.",
                    raw.get("id", "?"),
                )
                item.password = None
        elif legacy_plaintext:
            # Legacy plaintext password: load it and flag for re-encryption.
            item.password = legacy_plaintext
            self._needs_migration = True
        return item

    def _serialize(self, item: QueueItem) -> dict:
        data = asdict(item)
        data.pop("password", None)
        if item.password:
            # Only allow creating a fresh key when no encrypted secrets already
            # exist; otherwise creating a key would orphan those secrets.
            data["enc_password"] = self.secret_box.encrypt(
                item.password, allow_create=not self._had_encrypted_secrets
            )
        else:
            # Pass through an unrecoverable token unchanged rather than losing it.
            data["enc_password"] = getattr(item, "_enc_password", None)
        # Re-emit unknown fields last so they cannot shadow a known one.
        for key, value in getattr(item, "_extra", {}).items():
            data.setdefault(key, value)
        return data

    def _mark_corrupt(self, reason: str, data: bytes | None) -> None:
        """Flag the on-disk queue as corrupt, preserve it, and back it up once.

        The original is NEVER overwritten. A single timestamped copy is made
        the first time corruption is seen (checked under the file lock, so
        concurrent processes do not race or duplicate backups). No queue key
        is created while integrity is unknown.
        """
        self._corrupt = True
        self._had_encrypted_secrets = True  # refuse any key creation
        self.items = []
        # Preserve THIS episode's bytes (deduplicated by content hash, so a
        # backup from an earlier, different corruption never suppresses it).
        # `_load` always runs under the file lock, so concurrent detectors
        # cannot duplicate or lose the backup.
        self._corrupt_backup = preserve_corrupt_file(self.path, data) if data is not None else None
        if self._corrupt_backup is not None:
            self._corrupt_reason = (
                f"The transfer queue file is corrupt and was preserved: {reason}. "
                f"A backup was saved as {self._corrupt_backup.name}; resolve it with "
                "`mb queue reset` (discards jobs) or restore a good copy."
            )
        else:
            # Never claim a backup that was not written.
            self._corrupt_reason = (
                f"The transfer queue file is corrupt and was preserved: {reason}. "
                "A backup could NOT be written; fix the permissions or move the file "
                "aside, then run `mb queue reset`."
            )

    def _load(self) -> None:
        self._needs_migration = False
        self._corrupt = False
        self._corrupt_reason = ""
        self._corrupt_backup = None
        # Conservative default: assume secrets may exist until we have parsed
        # the file, so we never auto-create a key over a malformed queue.
        self._had_encrypted_secrets = False
        if not self.path.exists():
            self.items = []
            return
        try:
            raw = self.path.read_bytes()
        except OSError as exc:
            self._mark_corrupt(f"unreadable ({exc})", None)
            return
        try:
            data = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self._mark_corrupt(f"not valid JSON ({exc})", raw)
            return
        # Schema: root must be a JSON list of objects.
        if not isinstance(data, list):
            self._mark_corrupt(f"root is {type(data).__name__}, expected a list", raw)
            return
        try:
            validated = [validate_raw_item(entry) for entry in data]
            validate_unique_ids(validated)
        except QueueCorruptionError as exc:
            self._mark_corrupt(str(exc), raw)
            return
        # Only now — with the whole file validated — build items. Never
        # partially load and then rewrite.
        self._had_encrypted_secrets = any(entry.get("enc_password") for entry in validated)
        try:
            self.items = [self._deserialize(entry) for entry in validated]
        except (TypeError, ValueError, KeyError) as exc:
            # Belt and braces: a dataclass-construction error is corruption,
            # never a raw Python exception surfacing in the CLI.
            self._mark_corrupt(f"entry could not be loaded ({type(exc).__name__})", raw)
            return
        # Rewrite once to encrypt any legacy plaintext passwords found on load.
        # If the key cannot be created safely, preserve the original file.
        if self._needs_migration:
            try:
                self.save()
            except QueueKeyError as exc:
                log.warning("Could not migrate legacy queue secrets: %s", exc)

    def save(self) -> None:
        with self._locked():
            # Never overwrite a corrupt queue file: every mutation funnels
            # through save(), so this one guard blocks add/remove/claim/status/
            # heartbeat/retry/clear while integrity is unknown.
            self._ensure_writable()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Serialize BEFORE touching the filesystem so a serialization
            # failure preserves the original file untouched.
            payload = json.dumps([self._serialize(i) for i in self.items], indent=2)
            atomic_write_text(self.path, payload)

    def add(self, item: QueueItem) -> str:
        import datetime as dt

        with self._locked():
            self._load()
            if not item.id:
                item.id = QueueItem.new_id()
            if not item.created_iso:
                item.created_iso = dt.datetime.now(dt.timezone.utc).isoformat()
            self.items.append(item)
            self.save()
            return item.id

    def remove(self, item_id: str) -> bool:
        with self._locked():
            self._load()
            before = len(self.items)
            self.items = [i for i in self.items if i.id != item_id]
            if len(self.items) != before:
                self.save()
                return True
            return False

    @staticmethod
    def _owns(item: QueueItem, run_id: str, lease_epoch: int | None) -> bool:
        return item.run_id == run_id and (lease_epoch is None or item.lease_epoch == lease_epoch)

    @staticmethod
    def _check_owner(item: QueueItem, run_id: str | None, lease_epoch: int | None) -> None:
        """Refuse a mutation from a run that no longer holds the lease.

        Callers that pass no ``run_id`` are administrative (CLI `retry`/`remove`,
        recovery, tests): they are the operator acting deliberately, not a
        runner racing another runner. A caller that DOES present a lease must
        still hold it.
        """
        if run_id is None:
            return
        if not QueueManager._owns(item, run_id, lease_epoch):
            raise QueueOwnershipError(
                f"Run {run_id} no longer owns job {item.id} "
                f"(it is now {item.status} under {item.run_id or 'no run'}); "
                "the write was refused."
            )

    def _is_lease_live(self, item: QueueItem, lease_seconds: int) -> bool:
        """True when this active job's owner is still heartbeating."""
        import datetime as dt

        if item.status != JobStatus.ACTIVE.value or not item.heartbeat_iso:
            return False
        try:
            beat = dt.datetime.fromisoformat(item.heartbeat_iso)
        except ValueError:
            return False
        return (dt.datetime.now(dt.timezone.utc) - beat).total_seconds() <= lease_seconds

    def update_status(
        self,
        item_id: str,
        status: JobStatus,
        error: str | None = None,
        run_id: str | None = None,
        lease_epoch: int | None = None,
    ) -> None:
        """Set a job's status. When ``run_id`` is given, the lease is verified
        first and a write from a lost lease raises QueueOwnershipError."""
        import datetime as dt

        with self._locked():
            self._load()
            for item in self.items:
                if item.id == item_id:
                    self._check_owner(item, run_id, lease_epoch)
                    item.status = status.value
                    if error:
                        item.error = error
                    if status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELED):
                        item.finished_iso = dt.datetime.now(dt.timezone.utc).isoformat()
                    if status in (
                        JobStatus.DONE,
                        JobStatus.FAILED,
                        JobStatus.CANCELED,
                        JobStatus.INTERRUPTED,
                        JobStatus.PENDING,
                    ):
                        item.run_id = None
                        item.heartbeat_iso = None
                    break
            self.save()

    def mark_active(
        self, item_id: str, run_id: str, lease_seconds: int = LEASE_SECONDS
    ) -> int | None:
        """Lease a job to this run: active + owner + fresh heartbeat.

        Starts a NEW lease generation. Refuses to steal a lease another run is
        still heartbeating; returns the new generation, or None if the job is
        gone.
        """
        import datetime as dt

        with self._locked():
            self._load()
            now = dt.datetime.now(dt.timezone.utc).isoformat()
            for item in self.items:
                if item.id == item_id:
                    if item.run_id != run_id and self._is_lease_live(item, lease_seconds):
                        raise QueueOwnershipError(
                            f"Job {item_id} is actively leased to run {item.run_id}; "
                            f"run {run_id} cannot take it over."
                        )
                    item.status = JobStatus.ACTIVE.value
                    item.run_id = run_id
                    item.heartbeat_iso = now
                    item.lease_epoch += 1
                    self.save()
                    return item.lease_epoch
            self.save()
            return None

    def touch(self, item_id: str, run_id: str, lease_epoch: int | None = None) -> bool:
        """Refresh the heartbeat of a job this run owns and that is still active.

        Returns True when the heartbeat was applied. A False return means this
        run NO LONGER OWNS the job (it finished elsewhere, was recovered, or
        was re-leased) — the caller must stop the in-flight work instead of
        racing the new owner.

        Reloads the newest state first, so a heartbeat can never revert a
        DONE/FAILED/CANCELED status written by another thread or process.
        """
        import datetime as dt

        with self._locked():
            self._load()
            for item in self.items:
                if item.id != item_id:
                    continue
                if not self._owns(item, run_id, lease_epoch):
                    return False
                if item.status != JobStatus.ACTIVE.value:
                    return False
                item.heartbeat_iso = dt.datetime.now(dt.timezone.utc).isoformat()
                self.save()
                return True
            return False

    def _recover_interrupted_locked(self, lease_seconds: int) -> list[QueueItem]:
        """Recovery pass over the freshly loaded items; caller holds the lock."""
        import datetime as dt

        now = dt.datetime.now(dt.timezone.utc)
        recovered: list[QueueItem] = []
        for item in self.items:
            if item.status != JobStatus.ACTIVE.value:
                continue
            stale = True
            if item.heartbeat_iso:
                try:
                    beat = dt.datetime.fromisoformat(item.heartbeat_iso)
                    stale = (now - beat).total_seconds() > lease_seconds
                except ValueError:
                    stale = True
            if stale:
                item.status = JobStatus.INTERRUPTED.value
                item.run_id = None
                item.heartbeat_iso = None
                recovered.append(item)
        return recovered

    def recover_interrupted(self, lease_seconds: int = LEASE_SECONDS) -> list[QueueItem]:
        """Mark abandoned active jobs (stale/missing heartbeat) as interrupted.

        A live run keeps heartbeating its active job, so jobs inside the lease
        window are never stolen. Jobs whose owner stopped heartbeating (crash,
        reboot, kill) become INTERRUPTED and are re-run by `claim_next`.
        Returns the recovered items.
        """
        with self._locked():
            self._load()
            recovered = self._recover_interrupted_locked(lease_seconds)
            if recovered:
                self.save()
            return recovered

    def claim_next(self, run_id: str, lease_seconds: int = LEASE_SECONDS) -> QueueItem | None:
        """Atomically claim the next runnable job for this run.

        Under ONE lock acquisition: reload the newest queue, recover stale
        active jobs, pick the first pending/interrupted job, lease it
        (active + owner + heartbeat), persist, and return it. Two competing
        runners (threads, instances, or processes) can never claim the same
        job because the whole read-modify-write is serialized by the file
        lock.
        """
        import datetime as dt

        with self._locked():
            self._load()
            recovered = self._recover_interrupted_locked(lease_seconds)
            chosen: QueueItem | None = None
            for item in self.items:
                if item.status in (JobStatus.PENDING.value, JobStatus.INTERRUPTED.value):
                    chosen = item
                    break
            if chosen is not None:
                chosen.status = JobStatus.ACTIVE.value
                chosen.run_id = run_id
                chosen.heartbeat_iso = dt.datetime.now(dt.timezone.utc).isoformat()
                # New generation: any writer still holding the previous lease
                # (a stalled run whose heartbeat died) is locked out from here.
                chosen.lease_epoch += 1
            if chosen is not None or recovered:
                self.save()
            return chosen

    def retry(self, item_id: str) -> bool:
        """Return a failed/interrupted/canceled job to pending."""
        with self._locked():
            self._load()
            for item in self.items:
                if item.id == item_id and item.status in (
                    JobStatus.FAILED.value,
                    JobStatus.INTERRUPTED.value,
                    JobStatus.CANCELED.value,
                ):
                    item.status = JobStatus.PENDING.value
                    item.error = None
                    item.finished_iso = None
                    item.run_id = None
                    item.heartbeat_iso = None
                    self.save()
                    return True
            return False

    def pending(self) -> list[QueueItem]:
        return [i for i in self.items if i.status == JobStatus.PENDING.value]

    def runnable(self) -> list[QueueItem]:
        """Jobs the next run should process: pending plus recovered interrupted."""
        return [
            i
            for i in self.items
            if i.status in (JobStatus.PENDING.value, JobStatus.INTERRUPTED.value)
        ]

    def clear_done(self) -> int:
        with self._locked():
            self._load()
            before = len(self.items)
            self.items = [
                i
                for i in self.items
                if i.status not in (JobStatus.DONE.value, JobStatus.CANCELED.value)
            ]
            if len(self.items) != before:
                self.save()
            return before - len(self.items)

    @property
    def is_corrupt(self) -> bool:
        return self._corrupt

    @property
    def corrupt_backup(self) -> Path | None:
        """Backup holding THIS episode's bytes, or None if none was written."""
        return self._corrupt_backup

    def reset(self) -> None:
        """Explicit recovery: discard a corrupt/current queue and start empty.

        The corrupt original was already backed up on load; this writes a
        fresh empty queue so mutations can resume.
        """
        with self._locked():
            self._corrupt = False
            self._corrupt_reason = ""
            self._had_encrypted_secrets = False
            self.items = []
            self.save()
