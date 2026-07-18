"""Persistent transfer queue.

Stores a JSON list of pending/active/failed transfers so the CLI can pick
them up across runs. Each item is one download or upload job.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import datetime as dt
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

from ..utils.corruption import preserve_corrupt_file
from ..utils.filelock import FileLock, FileLockError

log = logging.getLogger(__name__)


class QueueLockError(Exception):
    """Raised when the cross-process queue lock cannot be acquired in time."""


class QueueCorruptionError(Exception):
    """Raised when the queue file is malformed or has an invalid schema.

    A corrupt queue is preserved (never overwritten) and mutations are blocked
    until the operator resolves it with `queue reset` or manual recovery.
    """


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


# Statuses that own a finish time. `update_status` writes `finished_iso` for
# exactly these.
_TERMINAL_STATUSES = frozenset(
    {JobStatus.DONE.value, JobStatus.FAILED.value, JobStatus.CANCELED.value}
)


def _validate_iso_timestamp(name: str, value) -> None:
    """Require a timezone-aware ISO-8601 timestamp, or the legacy empty string.

    Everything this CLI writes is `datetime.now(timezone.utc).isoformat()`, so
    a naive or unparsable value means the file was hand-edited or damaged. The
    empty string stays valid: files written before `created_iso` existed carry
    it, and the next save fills it in.
    """
    if value is None or value == "":
        return
    if not isinstance(value, str):
        raise QueueCorruptionError(f"queue entry field {name!r} must be a string")
    text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise QueueCorruptionError(
            f"queue entry field {name!r} is not a valid ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise QueueCorruptionError(
            f"queue entry field {name!r} must be timezone-aware (got a naive timestamp)"
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

    def __post_init__(self) -> None:
        # Fields written by a NEWER version, carried through untouched so a
        # round trip never silently drops them. Not persisted as a field
        # itself: `QueueManager._serialize` re-emits the contents.
        self._extra: dict = {}
        self._enc_password: str | None = None

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
            validated = [self._validate_raw_item(entry) for entry in data]
            self._validate_unique_ids(validated)
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

    _REQUIRED_ITEM_FIELDS = {
        "id": str,
        "type": str,
        "source": str,
        "destination": str,
    }
    # Persisted optional fields: a string or null when present. `password` is
    # the legacy plaintext form (re-encrypted on load); `enc_password` is the
    # sealed blob and is not a dataclass field.
    _OPTIONAL_STR_ITEM_FIELDS = (
        "error",
        "account",
        "password",
        "enc_password",
        "finished_iso",
        "run_id",
        "heartbeat_iso",
    )

    def _validate_raw_item(self, entry) -> dict:
        """Validate one raw queue entry's shape; raise QueueCorruptionError.

        Every shape/type/enum failure becomes QueueCorruptionError, so a raw
        TypeError/ValueError/KeyError from the dataclass constructor can never
        escape to the CLI.
        """
        if not isinstance(entry, dict):
            raise QueueCorruptionError(f"queue entry is {type(entry).__name__}, expected an object")
        for name, expected in self._REQUIRED_ITEM_FIELDS.items():
            if name not in entry:
                raise QueueCorruptionError(f"queue entry is missing required field {name!r}")
            if not isinstance(entry[name], expected):
                raise QueueCorruptionError(
                    f"queue entry field {name!r} must be {expected.__name__}"
                )
        if not entry["id"].strip():
            raise QueueCorruptionError("queue entry field 'id' must not be empty")
        # `type` is already known to be a str, so set membership is safe here.
        if entry["type"] not in {t.value for t in JobType}:
            raise QueueCorruptionError(f"queue entry has unknown type {entry['type']!r}")
        # Type check BEFORE set membership: an unhashable list/dict status
        # would raise a raw TypeError from `in`.
        status = entry.get("status", JobStatus.PENDING.value)
        if not isinstance(status, str):
            raise QueueCorruptionError(
                f"queue entry field 'status' is {type(status).__name__}, expected a string"
            )
        if status not in {s.value for s in JobStatus}:
            raise QueueCorruptionError(f"queue entry has unknown status {status!r}")
        # bool is a subclass of int; a boolean size is corruption, not 0/1.
        size = entry.get("size", 0)
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise QueueCorruptionError("queue entry field 'size' must be an integer >= 0")
        for name in self._OPTIONAL_STR_ITEM_FIELDS:
            value = entry.get(name)
            if value is not None and not isinstance(value, str):
                raise QueueCorruptionError(f"queue entry field {name!r} must be a string or null")
        # `source` is operationally required: a job with no URL/path can never
        # run and the CLI never writes one. `destination` is NOT checked - an
        # empty destination is a documented, CLI-written value meaning "use
        # config download_path" (upload jobs always store it empty).
        if not entry["source"].strip():
            raise QueueCorruptionError("queue entry field 'source' must not be blank")
        # Timestamps: strict timezone-aware ISO-8601. The empty string is the
        # documented legacy value (older files predate created_iso) and is
        # migrated on the next save; anything else malformed is corruption.
        for name in ("created_iso", "finished_iso", "heartbeat_iso"):
            _validate_iso_timestamp(name, entry.get(name))
        # State consistency: a lease belongs to an ACTIVE job only. Every
        # writer (`update_status`, `retry`, `claim_next`) already clears these
        # on any other status, so their presence means the file was edited or
        # damaged. An active job with no lease is NOT rejected: that is the
        # legacy/crashed-owner shape that `recover_interrupted` handles.
        if status != JobStatus.ACTIVE.value:
            for name in ("run_id", "heartbeat_iso"):
                if entry.get(name) is not None:
                    raise QueueCorruptionError(
                        f"queue entry with status {status!r} must not carry {name!r}"
                    )
        if status not in _TERMINAL_STATUSES and entry.get("finished_iso") is not None:
            raise QueueCorruptionError(
                f"queue entry with status {status!r} must not carry 'finished_iso'"
            )
        enc = entry.get("enc_password")
        if enc is not None:
            try:
                base64.b64decode(enc, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise QueueCorruptionError(
                    "queue entry field 'enc_password' is not valid base64"
                ) from exc
        return entry

    @staticmethod
    def _validate_unique_ids(entries: list[dict]) -> None:
        """Job ids address jobs: `remove`/`retry`/`update_status` would act on
        an arbitrary one of a duplicated pair, so duplicates are corruption."""
        seen: set[str] = set()
        for entry in entries:
            item_id = entry["id"]
            if item_id in seen:
                raise QueueCorruptionError(f"queue contains duplicate job id {item_id!r}")
            seen.add(item_id)

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
