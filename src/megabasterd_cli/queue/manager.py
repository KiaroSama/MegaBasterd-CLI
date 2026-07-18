"""Persistent transfer queue.

Stores a JSON list of pending/active/failed transfers so the CLI can pick
them up across runs. Each item is one download or upload job.
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import os
import tempfile
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field, fields
from enum import Enum
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger(__name__)


class QueueLockError(Exception):
    """Raised when the cross-process queue lock cannot be acquired in time."""


class _QueueFileLock:
    """Cross-platform advisory file lock guarding queue read-modify-write.

    Uses `msvcrt.locking` on Windows and `fcntl.flock` on POSIX. Both block
    other processes AND other open descriptors in the same process, so two
    `QueueManager` instances anywhere are serialized. Acquisition is bounded
    by a timeout and never silently skipped.
    """

    def __init__(self, path: Path):
        self.path = path
        self._fd: int | None = None

    def acquire(self, timeout: float) -> None:
        deadline = time.monotonic() + max(0.0, timeout)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR)
        try:
            while True:
                try:
                    if os.name == "nt":
                        # msvcrt only exists on Windows; fcntl only on POSIX.
                        # Each platform's module is invisible to mypy on the
                        # other, so both branches are attribute-ignored.
                        import msvcrt  # type: ignore[import-not-found, unused-ignore]

                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(  # type: ignore[attr-defined, unused-ignore]
                            fd,
                            msvcrt.LK_NBLCK,  # type: ignore[attr-defined, unused-ignore]
                            1,
                        )
                    else:
                        import fcntl  # type: ignore[import-not-found, unused-ignore]

                        fcntl.flock(  # type: ignore[attr-defined, unused-ignore]
                            fd,
                            fcntl.LOCK_EX | fcntl.LOCK_NB,  # type: ignore[attr-defined, unused-ignore]
                        )
                    self._fd = fd
                    return
                except OSError:
                    if time.monotonic() >= deadline:
                        raise QueueLockError(
                            f"Could not lock the transfer queue within {timeout:.0f}s; "
                            f"another queue operation is holding {self.path.name}. "
                            "Retry after it finishes."
                        ) from None
                    time.sleep(0.05)
        except BaseException:
            if self._fd is None:
                os.close(fd)
            raise

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            if os.name == "nt":
                import msvcrt  # type: ignore[import-not-found, unused-ignore]

                os.lseek(fd, 0, os.SEEK_SET)
                with contextlib.suppress(OSError):
                    msvcrt.locking(  # type: ignore[attr-defined, unused-ignore]
                        fd,
                        msvcrt.LK_UNLCK,  # type: ignore[attr-defined, unused-ignore]
                        1,
                    )
            else:
                import fcntl  # type: ignore[import-not-found, unused-ignore]

                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)  # type: ignore[attr-defined, unused-ignore]
        finally:
            os.close(fd)


# Associated data tag so a queue secret blob cannot be reused in another context.
_QUEUE_SECRET_AAD = b"megabasterd-cli/queue-secret"
_QUEUE_KEY_LEN = 32
_QUEUE_SECRET_VERSION = 1  # First byte of the decoded blob (self-identifying).


class QueueKeyError(Exception):
    """Raised when the local queue key file is present but corrupt."""


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

    @staticmethod
    def new_id() -> str:
        return uuid.uuid4().hex[:12]


class QueueSecretBox:
    """Encrypts queue item secrets at rest with a locally stored random key.

    A 32-byte key is generated once and stored next to the queue file with
    restrictive permissions. Secrets are sealed with AES-256-GCM and stored as a
    self-identifying, versioned blob. This keeps plaintext passwords out of
    ``queue.json`` (and any backup/sync of it) while preserving non-interactive
    queue runs (no passphrase prompt).

    Threat model: this does NOT protect against an attacker who can read BOTH
    ``queue.json`` and the key file; possession of both allows recovery of the
    secret. On Windows the file is created with normal user permissions (no
    POSIX mode bits). For stronger protection, run the queue with an unlocked
    credential vault instead.
    """

    def __init__(self, key_path: Path):
        self.key_path = key_path
        self._key: bytes | None = None

    def load_key(self, create: bool) -> bytes | None:
        """Return the queue key, or None when it is absent and create is False.

        A non-empty key file of the wrong length is treated as corruption and
        is never silently replaced (that would orphan existing secrets). An
        empty/partial file is recreated only when ``create`` is True.
        """
        if self._key is not None:
            return self._key
        empty_recover = False
        if self.key_path.exists():
            data = self.key_path.read_bytes()
            if len(data) == _QUEUE_KEY_LEN:
                self._key = data
                return data
            if len(data) == 0:
                if not create:
                    return None
                log.warning("Queue key file is empty; generating a new key")
                empty_recover = True
            else:
                # Non-empty but wrong length means corruption; do not replace.
                raise QueueKeyError(
                    f"Queue key file has unexpected length {len(data)}; refusing to use it"
                )
        if not create:
            return None
        key = os.urandom(_QUEUE_KEY_LEN)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        if empty_recover:
            # Overwrite the empty placeholder atomically.
            tmp = self.key_path.with_suffix(self.key_path.suffix + ".tmp")
            tmp.write_bytes(key)
            os.replace(tmp, self.key_path)
        else:
            # Race-safe exclusive create: if another process created the key
            # first, adopt the existing valid key instead of clobbering it.
            try:
                fd = os.open(str(self.key_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                existing = self.key_path.read_bytes()
                if len(existing) == _QUEUE_KEY_LEN:
                    self._key = existing
                    return existing
                raise QueueKeyError("Queue key file appeared but is invalid") from None
            with os.fdopen(fd, "wb") as f:
                f.write(key)
        with contextlib.suppress(OSError, AttributeError):
            os.chmod(self.key_path, 0o600)
        self._key = key
        return key

    def encrypt(self, plaintext: str, allow_create: bool = True) -> str:
        """Encrypt a queue secret. When ``allow_create`` is False and no valid
        key exists, raise instead of creating one (used when other encrypted
        secrets already exist, to avoid orphaning them)."""
        key = self.load_key(create=allow_create)
        if key is None:
            raise QueueKeyError(
                "No queue key is available to encrypt the secret and creating a new "
                "one is refused because encrypted queue secrets already exist"
            )
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), _QUEUE_SECRET_AAD)
        blob = bytes([_QUEUE_SECRET_VERSION]) + nonce + ct
        return base64.b64encode(blob).decode("ascii")

    def decrypt(self, token: str) -> str:
        # Decryption never creates a key; a missing key means the secret is
        # currently unrecoverable (the caller preserves the original blob).
        key = self.load_key(create=False)
        if key is None:
            raise QueueKeyError("Queue key is missing; cannot decrypt the stored secret")
        raw = base64.b64decode(token)
        # Accept the versioned blob (v1) and, for forward safety, an unversioned
        # legacy blob (nonce||ct) produced by an earlier build of this branch.
        if raw and raw[0] == _QUEUE_SECRET_VERSION and len(raw) >= 1 + 12 + 16:
            nonce, ct = raw[1:13], raw[13:]
        elif len(raw) >= 12 + 16:
            nonce, ct = raw[:12], raw[12:]
        else:
            raise ValueError("Queue secret blob too short")
        return AESGCM(key).decrypt(nonce, ct, _QUEUE_SECRET_AAD).decode("utf-8")


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
        self._file_lock = _QueueFileLock(path.parent / (path.name + ".lock"))
        self._lock_depth = 0
        with self._locked():
            self._load()

    @contextlib.contextmanager
    def _locked(self):
        """Hold the instance mutex plus the cross-process file lock (once)."""
        with self._mutex:
            if self._lock_depth == 0:
                self._file_lock.acquire(timeout=self.lock_timeout)
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
                if self._lock_depth == 0:
                    self._file_lock.release()

    def _deserialize(self, raw: dict) -> QueueItem:
        raw = dict(raw)
        enc = raw.pop("enc_password", None)
        legacy_plaintext = raw.pop("password", None)
        item = QueueItem(**{k: v for k, v in raw.items() if k in self._field_names})
        # Preserve the raw encrypted token so an unrecoverable secret is never
        # silently dropped when the queue is rewritten.
        item._enc_password = enc  # type: ignore[attr-defined]
        if enc:
            try:
                item.password = self.secret_box.decrypt(enc)
                item._enc_password = None  # type: ignore[attr-defined]
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
        return data

    def _load(self) -> None:
        self._needs_migration = False
        # Conservative default: assume secrets may exist until we have parsed
        # the file, so we never auto-create a key over a malformed queue.
        self._had_encrypted_secrets = False
        if not self.path.exists():
            self.items = []
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError, TypeError):
            # Malformed/unreadable queue: do not rewrite it and do not create a
            # key. Treat as possibly holding secrets so key creation is refused.
            self._had_encrypted_secrets = True
            self.items = []
            return
        # Determine up front whether any encrypted secrets already exist; this
        # governs whether a missing/empty key may be safely (re)created.
        try:
            self._had_encrypted_secrets = any(
                isinstance(i, dict) and i.get("enc_password") for i in data
            )
            self.items = [self._deserialize(i) for i in data]
        except (TypeError, AttributeError):
            self._had_encrypted_secrets = True
            self.items = []
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
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Serialize BEFORE touching the filesystem so a serialization
            # failure preserves the original file untouched.
            payload = json.dumps([self._serialize(i) for i in self.items], indent=2)
            # Unique temp file per save: concurrent savers can never collide
            # on one temp name.
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=self.path.name + ".",
                suffix=".tmp",
                delete=False,
            ) as tf:
                tf.write(payload)
                tf.flush()
                os.fsync(tf.fileno())
                tmp_path = tf.name
            for attempt in range(5):
                try:
                    os.replace(tmp_path, self.path)
                    break
                except PermissionError:
                    # Windows: transient lock by AV/another replace.
                    if attempt == 4:
                        raise
                    time.sleep(0.05 * (attempt + 1))
            # Best effort: persist the directory entry on POSIX.
            if hasattr(os, "O_DIRECTORY"):
                with contextlib.suppress(OSError):
                    dfd = os.open(str(self.path.parent), os.O_RDONLY)
                    try:
                        os.fsync(dfd)
                    finally:
                        os.close(dfd)

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

    def update_status(self, item_id: str, status: JobStatus, error: str | None = None) -> None:
        import datetime as dt

        with self._locked():
            self._load()
            for item in self.items:
                if item.id == item_id:
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

    def mark_active(self, item_id: str, run_id: str) -> None:
        """Lease a job to this run: active + owner + fresh heartbeat."""
        import datetime as dt

        with self._locked():
            self._load()
            now = dt.datetime.now(dt.timezone.utc).isoformat()
            for item in self.items:
                if item.id == item_id:
                    item.status = JobStatus.ACTIVE.value
                    item.run_id = run_id
                    item.heartbeat_iso = now
                    break
            self.save()

    def touch(self, item_id: str, run_id: str) -> None:
        """Refresh the heartbeat of a job this run owns and that is still active.

        Reloads the newest state first, so a heartbeat can never revert a
        DONE/FAILED/CANCELED status written by another thread or process.
        """
        import datetime as dt

        with self._locked():
            self._load()
            for item in self.items:
                if (
                    item.id == item_id
                    and item.run_id == run_id
                    and item.status == JobStatus.ACTIVE.value
                ):
                    item.heartbeat_iso = dt.datetime.now(dt.timezone.utc).isoformat()
                    self.save()
                    break

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
