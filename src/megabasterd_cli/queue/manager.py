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
import uuid
from dataclasses import asdict, dataclass, field, fields
from enum import Enum
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger(__name__)

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

    def _load_or_create_key(self) -> bytes:
        if self._key is not None:
            return self._key
        empty_recover = False
        if self.key_path.exists():
            data = self.key_path.read_bytes()
            if len(data) == _QUEUE_KEY_LEN:
                self._key = data
                return data
            if len(data) == 0:
                # Empty/partial file (e.g. interrupted write): recreate it.
                log.warning("Queue key file is empty; generating a new key")
                empty_recover = True
            else:
                # Non-empty but wrong length means corruption; do not silently
                # replace it (that would orphan existing secrets without notice).
                raise QueueKeyError(
                    f"Queue key file has unexpected length {len(data)}; refusing to use it"
                )
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

    def encrypt(self, plaintext: str) -> str:
        nonce = os.urandom(12)
        ct = AESGCM(self._load_or_create_key()).encrypt(
            nonce, plaintext.encode("utf-8"), _QUEUE_SECRET_AAD
        )
        blob = bytes([_QUEUE_SECRET_VERSION]) + nonce + ct
        return base64.b64encode(blob).decode("ascii")

    def decrypt(self, token: str) -> str:
        raw = base64.b64decode(token)
        # Accept the versioned blob (v1) and, for forward safety, an unversioned
        # legacy blob (nonce||ct) produced by an earlier build of this branch.
        if raw and raw[0] == _QUEUE_SECRET_VERSION and len(raw) >= 1 + 12 + 16:
            nonce, ct = raw[1:13], raw[13:]
        elif len(raw) >= 12 + 16:
            nonce, ct = raw[:12], raw[12:]
        else:
            raise ValueError("Queue secret blob too short")
        return (
            AESGCM(self._load_or_create_key()).decrypt(nonce, ct, _QUEUE_SECRET_AAD).decode("utf-8")
        )


class QueueManager:
    """JSON-file backed transfer queue."""

    def __init__(self, path: Path, secret_box: QueueSecretBox | None = None):
        self.path = path
        self.secret_box = secret_box or QueueSecretBox(path.parent / "queue.key")
        self.items: list[QueueItem] = []
        self._field_names = {f.name for f in fields(QueueItem)}
        self._load()

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
            data["enc_password"] = self.secret_box.encrypt(item.password)
        else:
            # Pass through an unrecoverable token unchanged rather than losing it.
            data["enc_password"] = getattr(item, "_enc_password", None)
        return data

    def _load(self) -> None:
        self._needs_migration = False
        if not self.path.exists():
            self.items = []
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            self.items = [self._deserialize(i) for i in data]
        except (json.JSONDecodeError, OSError, TypeError):
            self.items = []
            return
        # Rewrite once to encrypt any legacy plaintext passwords found on load.
        if self._needs_migration:
            self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump([self._serialize(i) for i in self.items], f, indent=2)
        os.replace(tmp, self.path)

    def add(self, item: QueueItem) -> str:
        import datetime as dt

        if not item.id:
            item.id = QueueItem.new_id()
        if not item.created_iso:
            item.created_iso = dt.datetime.now(dt.timezone.utc).isoformat()
        self.items.append(item)
        self.save()
        return item.id

    def remove(self, item_id: str) -> bool:
        before = len(self.items)
        self.items = [i for i in self.items if i.id != item_id]
        if len(self.items) != before:
            self.save()
            return True
        return False

    def update_status(self, item_id: str, status: JobStatus, error: str | None = None) -> None:
        import datetime as dt

        for item in self.items:
            if item.id == item_id:
                item.status = status.value
                if error:
                    item.error = error
                if status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELED):
                    item.finished_iso = dt.datetime.now(dt.timezone.utc).isoformat()
                break
        self.save()

    def pending(self) -> list[QueueItem]:
        return [i for i in self.items if i.status == JobStatus.PENDING.value]

    def clear_done(self) -> int:
        before = len(self.items)
        self.items = [
            i
            for i in self.items
            if i.status not in (JobStatus.DONE.value, JobStatus.CANCELED.value)
        ]
        if len(self.items) != before:
            self.save()
        return before - len(self.items)
