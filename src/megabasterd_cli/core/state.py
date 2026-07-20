"""Persistent state for resumable transfers.

A state file records which chunks of a download/upload have completed so the
transfer can resume after interruption. The file lives next to the destination
with a `.mbstate` suffix and is rewritten atomically after each chunk completes.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .errors import MegaError

log = logging.getLogger(__name__)
STATE_FORMAT_VERSION = 1

# Serializes concurrent saves from parallel chunk workers *inside this process*;
# on Windows two simultaneous os.replace() calls onto the same target (or a
# virus scanner holding the fresh file) raise PermissionError. Cross-process
# safety comes from the file lock in `_state_lock_for`.
_save_lock = threading.Lock()

# How long a writer waits for the cross-process state lock before giving up.
STATE_LOCK_TIMEOUT = 10.0

_MAC_HEX_LENGTH = 32  # 16-byte CBC-MAC, hex-encoded
_MAC_BYTE_LENGTH = _MAC_HEX_LENGTH // 2
_VALID_TRANSFER_TYPES = frozenset({"download", "upload"})

# Hex-encoded metadata fields the transfer code decodes with bytes.fromhex.
_AES_KEY_HEX_LENGTH = 32  # 16-byte AES key
_NONCE_HEX_LENGTH = 16  # 8-byte nonce
# The uploader already bounds a completion-token response at 4096 bytes
# (MAX_UPLOAD_RESPONSE_BYTES); the stored hex form is twice that at most.
_MAX_TOKEN_HEX_LENGTH = 8192

# An `upload_url` in a state file is attacker-controllable in exactly the way a
# link-supplied ELC/MegaCrypter endpoint is: the uploader POSTs the whole local
# file there. MEGA hands out upload slots on its own storage domains only, so
# the host is pinned the same way `links.py` and the CONNECT proxy pin theirs.
_UPLOAD_HOST_SUFFIXES = ("mega.nz", "mega.co.nz")


class StateDurabilityError(MegaError):
    """The transferred DATA could not be forced to disk, so nothing may commit.

    `save_state` fsyncs the state file, which means a state file easily
    outlives the bytes it describes. Resume trusts it and SKIPS those chunks,
    producing a silently wrong output file.

    A failed flush therefore cannot be a warning: if the barrier did not hold,
    the snapshot behind it must not be written. A `MegaError` so every existing
    command handler already reports it as a normal failure - non-zero exit with
    a sanitized message - rather than a traceback.
    """


class StateCorruptionError(Exception):
    """A `.mbstate` file is unusable: malformed, mistyped, or inconsistent.

    Also raised by the WRITE path (`mark_chunk_done`) for a value this module
    would refuse to read back. The two paths must agree: a write that produces
    a file the reader quarantines costs the operator the ENTIRE resume state,
    when the correct answer is to reject the one bad value at its source.
    """


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise StateCorruptionError(message)


def _validate_chunk_index(value, seen: set[int]) -> None:
    # bool is an int subclass; `True` as a chunk index is corruption, not 1.
    _require(
        isinstance(value, int) and not isinstance(value, bool),
        f"completed_chunks entry {value!r} is not an integer",
    )
    _require(value >= 0, f"completed_chunks entry {value} is negative")
    _require(value not in seen, f"completed_chunks contains duplicate index {value}")
    seen.add(value)


def _validate_hex(value, label: str, *, length: int | None = None, max_length: int | None = None):
    _require(isinstance(value, str), f"metadata {label!r} must be a hex string")
    if length is not None:
        _require(len(value) == length, f"metadata {label!r} must be {length} hex characters")
    if max_length is not None:
        _require(
            0 < len(value) <= max_length,
            f"metadata {label!r} must be 1..{max_length} hex characters",
        )
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise StateCorruptionError(f"metadata {label!r} is not valid hex") from exc


def _validate_upload_url(value) -> None:
    """Refuse any upload endpoint a `.mbstate` file must not be able to name.

    A state file is untrusted input: it is a plain JSON file in a predictable
    location. Pointing `upload_url` at an attacker's host (with an attacker's
    `aes_key`) turns the next resume into a full exfiltration of the local
    file under a key the attacker chose. `validate_safe_target` is the repo's
    existing control for a link-supplied endpoint (HTTPS, no userinfo, no
    non-global IP); the host suffix pin is what stops a perfectly "safe"
    HTTPS host that simply is not MEGA.
    """
    from .link_services import UnsafeTargetError, validate_safe_target

    _require(isinstance(value, str), "metadata 'upload_url' must be a string")
    try:
        validate_safe_target(value, what="upload")
    except UnsafeTargetError as exc:
        raise StateCorruptionError(f"metadata 'upload_url' is unsafe: {exc}") from exc
    host = (urlparse(value).hostname or "").rstrip(".").lower()
    _require(
        any(host == suffix or host.endswith("." + suffix) for suffix in _UPLOAD_HOST_SUFFIXES),
        f"metadata 'upload_url' points at {host!r}, which is not a MEGA storage host",
    )


def _validate_metadata(metadata) -> None:
    """Type/length/destination-check every metadata key a transfer reads.

    `isinstance(metadata, dict)` was the whole check. Everything below was
    therefore decoded blind by the downloader and uploader - and
    `bytes.fromhex` raises TypeError (not ValueError) on a JSON number, so a
    poisoned file escaped the uploader's clear-and-retry self-heal entirely
    and broke every subsequent attempt.
    """
    _require(isinstance(metadata, dict), "state field 'metadata' must be an object")

    if "aes_key" in metadata:
        _validate_hex(metadata["aes_key"], "aes_key", length=_AES_KEY_HEX_LENGTH)
    if "nonce" in metadata:
        _validate_hex(metadata["nonce"], "nonce", length=_NONCE_HEX_LENGTH)
    if "completion_token" in metadata:
        _validate_hex(
            metadata["completion_token"], "completion_token", max_length=_MAX_TOKEN_HEX_LENGTH
        )
    if "upload_url" in metadata:
        _validate_upload_url(metadata["upload_url"])
    if "source_identity" in metadata:
        _require(
            isinstance(metadata["source_identity"], dict),
            "metadata 'source_identity' must be an object",
        )


def validate_state_dict(data) -> dict:
    """Validate a parsed `.mbstate` document, or raise StateCorruptionError.

    Valid JSON is not valid state. Without this, a hand-edited or truncated
    file reached the transfer code as a `TransferState` whose fields had the
    wrong types - and an invalid MAC only exploded much later, as a raw
    `ValueError` out of `bytes.fromhex` during chunk verification.
    """
    _require(isinstance(data, dict), f"state root is {type(data).__name__}, expected an object")

    version = data.get("format_version", STATE_FORMAT_VERSION)
    _require(
        isinstance(version, int) and not isinstance(version, bool),
        "format_version must be an integer",
    )

    for name in ("transfer_type", "source", "destination"):
        _require(name in data, f"state is missing required field {name!r}")
        _require(isinstance(data[name], str), f"state field {name!r} must be a string")
    _require(
        data["transfer_type"] in _VALID_TRANSFER_TYPES,
        f"state has unknown transfer_type {data['transfer_type']!r}",
    )

    _require("total_size" in data, "state is missing required field 'total_size'")
    total_size = data["total_size"]
    _require(
        isinstance(total_size, int) and not isinstance(total_size, bool),
        "state field 'total_size' must be an integer",
    )
    _require(total_size >= 0, "state field 'total_size' must not be negative")

    chunks = data.get("completed_chunks", [])
    _require(isinstance(chunks, list), "state field 'completed_chunks' must be a list")
    seen: set[int] = set()
    for entry in chunks:
        _validate_chunk_index(entry, seen)

    macs = data.get("chunk_macs", {})
    _require(isinstance(macs, dict), "state field 'chunk_macs' must be an object")
    normalized: dict[int, str] = {}
    for key, value in macs.items():
        try:
            index = int(key)
        except (TypeError, ValueError) as exc:
            raise StateCorruptionError(f"chunk_macs key {key!r} is not an integer") from exc
        _require(index >= 0, f"chunk_macs key {index} is negative")
        _require(isinstance(value, str), f"chunk_macs[{index}] must be a hex string")
        _require(
            len(value) == _MAC_HEX_LENGTH,
            f"chunk_macs[{index}] must be {_MAC_HEX_LENGTH} hex characters",
        )
        try:
            bytes.fromhex(value)  # reject invalid hex HERE, not during verification
        except ValueError as exc:
            raise StateCorruptionError(f"chunk_macs[{index}] is not valid hex") from exc
        normalized[index] = value

    metadata = data.get("metadata", {})
    _validate_metadata(metadata)

    revision = data.get("revision", 0)
    _require(
        isinstance(revision, int) and not isinstance(revision, bool),
        "state field 'revision' must be an integer",
    )
    _require(revision >= 0, "state field 'revision' must not be negative")

    # Semantic consistency: a MAC for a chunk that was never completed means the
    # two halves of the file disagree.
    orphans = set(normalized) - seen
    _require(not orphans, f"chunk_macs holds entries for uncompleted chunks {sorted(orphans)}")

    known = {
        "transfer_type",
        "source",
        "destination",
        "total_size",
        "format_version",
        "completed_chunks",
        "chunk_macs",
        "metadata",
        "revision",
    }
    return {
        **{k: v for k, v in data.items() if k in known},
        "format_version": version,
        "completed_chunks": list(chunks),
        "chunk_macs": normalized,
        "metadata": metadata,
        "revision": revision,
    }


def _state_lock_for(state_path: Path):
    """Cross-process advisory lock guarding one `.mbstate` file."""
    from ..utils.filelock import FileLock

    return FileLock(
        state_path.parent / (state_path.name + ".lock"),
        message=(
            f"Could not lock {state_path.name} within {STATE_LOCK_TIMEOUT:.0f}s; "
            "another transfer is updating it."
        ),
    )


@dataclass
class TransferState:
    """State for an in-progress transfer."""

    transfer_type: str  # "download" or "upload"
    source: str  # URL for download, file path for upload
    destination: str
    total_size: int
    format_version: int = STATE_FORMAT_VERSION
    completed_chunks: list[int] = field(default_factory=list)
    chunk_macs: dict[int, str] = field(default_factory=dict)  # hex-encoded MACs
    metadata: dict = field(default_factory=dict)
    # Monotonic generation, claimed by `snapshot_state` and enforced by
    # `save_state`: a snapshot older than what is already committed on disk is
    # refused instead of overwriting it.
    revision: int = 0

    @property
    def completed_set(self) -> set[int]:
        return set(self.completed_chunks)

    def is_chunk_done(self, index: int) -> bool:
        return index in self.completed_set

    def mark_chunk_done(self, index: int, mac: bytes | None = None) -> None:
        # Reject a MAC the reader would reject, at the point it enters the
        # state. Stored anyway, `load_state` quarantines the WHOLE file and the
        # transfer loses every completed chunk over one bad value.
        if mac is not None and len(mac) != _MAC_BYTE_LENGTH:
            raise StateCorruptionError(
                f"chunk {index} MAC is {len(mac)} bytes, expected {_MAC_BYTE_LENGTH}"
            )
        if index not in self.completed_set:
            self.completed_chunks.append(index)
        if mac is not None:
            self.chunk_macs[index] = mac.hex()

    def get_chunk_mac(self, index: int) -> bytes | None:
        hex_mac = self.chunk_macs.get(index)
        return bytes.fromhex(hex_mac) if hex_mac else None


def snapshot_state(state: TransferState) -> TransferState:
    """Return a shallow immutable-enough copy for serialization outside locks.

    Claims the next revision for the LIVE state as it copies. Callers take this
    snapshot under their own lock, so every snapshot carries a strictly
    increasing generation and `save_state` can tell a worker's stale view from
    a newer commit that already landed.
    """
    state.revision += 1
    return TransferState(
        revision=state.revision,
        format_version=state.format_version,
        transfer_type=state.transfer_type,
        source=state.source,
        destination=state.destination,
        total_size=state.total_size,
        completed_chunks=list(state.completed_chunks),
        chunk_macs=dict(state.chunk_macs),
        metadata=dict(state.metadata),
    )


def state_path_for(destination: str | Path) -> Path:
    """Compute the state file path for a destination."""
    p = Path(destination)
    return p.with_suffix(p.suffix + ".mbstate")


def load_state(destination: str | Path) -> TransferState | None:
    """Load existing state for a destination, or None when it cannot be trusted.

    Returning None means "start this transfer fresh", which is the project's
    existing resume UX (the same answer `auto_resume = false` produces). A
    malformed file is never partially trusted: it is quarantined byte-for-byte
    next to the destination first, so nothing is lost and the operator can
    inspect it. No raw AttributeError/TypeError/ValueError/KeyError from a
    damaged file can reach the CLI.
    """
    sp = state_path_for(destination)
    if not sp.exists():
        return None
    try:
        raw = sp.read_bytes()
    except OSError as exc:
        log.debug("Ignoring unreadable transfer state %s: %s", sp, exc)
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _quarantine_state(sp, raw, f"not valid UTF-8 JSON ({type(exc).__name__})")
        return None
    try:
        fields_ = validate_state_dict(data)
    except StateCorruptionError as exc:
        _quarantine_state(sp, raw, str(exc))
        return None
    if fields_["format_version"] != STATE_FORMAT_VERSION:
        log.debug(
            "Ignoring unsupported transfer state version %s in %s",
            fields_["format_version"],
            sp,
        )
        return None
    try:
        return TransferState(**fields_)
    except (TypeError, ValueError) as exc:  # belt and braces
        _quarantine_state(sp, raw, f"could not be loaded ({type(exc).__name__})")
        return None


def _quarantine_state(state_path: Path, data: bytes, reason: str) -> None:
    """Preserve a corrupt `.mbstate`, then REMOVE it, before the restart.

    Preserving a copy and leaving the original was the worst of both: the
    rejected file keeps its (arbitrarily high) `revision`, and `_disk_guard`
    reads it back on every save of the transfer that replaced it - so the
    replacement, starting at revision 0, could never out-rank the file nobody
    would ever load again, and silently persisted no resume state at all.

    Preservation failing is the one case that keeps the file: losing the
    evidence is worse than the stale guard, which `_disk_guard` handles anyway.
    """
    from ..utils.corruption import preserve_corrupt_file

    log.warning("Ignoring corrupt transfer state %s: %s", state_path.name, reason)
    if preserve_corrupt_file(state_path, data) is None:
        log.warning("Keeping %s: its bytes could not be preserved.", state_path.name)
        return
    with contextlib.suppress(OSError):
        state_path.unlink()


def _disk_guard(state_path: Path) -> tuple[int, int]:
    """`(format_version, revision)` already committed at `state_path`.

    Returns the permissive `(STATE_FORMAT_VERSION, -1)` when there is nothing
    USABLE there: a missing, unparseable, or invalid file constrains nothing.
    Only a document `load_state` would actually hand to a transfer may outrank
    a live snapshot - it used to be enough to parse as JSON, so a file rejected
    by `validate_state_dict` still blocked every save of its replacement, and a
    fresh state (revision 0) could never out-rank it.

    The VERSION claim is read before validating, and a newer-format file is
    returned unvalidated: a v2 document is not required to satisfy this
    version's schema, and callers protect it by version, never by revision.
    """
    try:
        data = json.loads(state_path.read_bytes().decode("utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return STATE_FORMAT_VERSION, -1
    if not isinstance(data, dict):
        return STATE_FORMAT_VERSION, -1
    version, revision = data.get("format_version"), data.get("revision")
    if not isinstance(version, int) or isinstance(version, bool):
        version = STATE_FORMAT_VERSION
    if not isinstance(revision, int) or isinstance(revision, bool):
        revision = 0
    if version > STATE_FORMAT_VERSION:
        return version, revision
    try:
        validate_state_dict(data)
    except StateCorruptionError:
        return STATE_FORMAT_VERSION, -1
    return version, revision


def _flush_transferred_data(state: TransferState) -> None:
    """Force the transferred DATA to disk BEFORE the state vouches for it.

    Order matters more than either write alone: `save_state` fsyncs the state
    file, so after a crash the state can easily outlive the data it describes -
    resume then SKIPS chunks whose bytes never reached the platter and the
    output is silently wrong.

    A download writes its destination file directly, so it is flushed here.
    An upload has no local destination: its durability point is the endpoint's
    HTTP 200 for the chunk, which already happens before `mark_chunk_done`.

    Flushing from a second descriptor is sound - fsync/FlushFileBuffers act on
    the file, not on one handle's buffers.

    A FAILED flush raises. It used to warn and return, after which the caller
    committed a snapshot vouching for chunks whose bytes may never have reached
    the platter - the precise corruption this barrier exists to prevent, made
    invisible by the very failure that should have stopped it. Losing resume
    progress does beat corrupting it, but only if the loss is what happens.
    """
    if state.transfer_type != "download":
        return
    try:
        fd = os.open(state.destination, os.O_RDWR)
    except FileNotFoundError as exc:
        # The one tolerable open failure, and only while the snapshot vouches
        # for nothing: no destination yet AND no completed chunks. With chunks
        # recorded, a missing destination is the corruption case, not a benign
        # one - the file whose bytes the state claims is gone.
        if state.completed_chunks:
            raise StateDurabilityError(
                message=(
                    f"Destination {state.destination} is missing ({exc}) but the "
                    f"snapshot records {len(state.completed_chunks)} completed chunk(s); "
                    "refusing to record them as durable."
                )
            ) from exc
        log.debug("Not flushing %s before saving state: %s", state.destination, exc)
        return
    except OSError as exc:
        # Permission denied, sharing violation, EIO, descriptor exhaustion: the
        # barrier could not even be raised, so nothing may be vouched for.
        raise StateDurabilityError(
            message=(
                f"Could not open transferred data to flush it ({exc}); "
                "refusing to record those chunks as complete."
            )
        ) from exc
    try:
        os.fsync(fd)
    except OSError as exc:
        raise StateDurabilityError(
            message=(
                f"Could not flush transferred data to disk ({exc}); "
                "refusing to record those chunks as complete."
            )
        ) from exc
    finally:
        os.close(fd)


def save_state(state: TransferState) -> None:
    """Atomically save the state file.

    Two locks, two different races: the in-process mutex serializes this
    process's chunk workers, and the advisory FILE lock serializes independent
    CLI processes so a second process cannot interleave its own
    write-then-replace and lose committed chunks. Serialization happens before
    either lock is taken, so a serialization failure leaves the original file
    untouched and drops no temp file.

    Under the file lock the committed file is READ back before it is replaced,
    and the write is refused when the state on disk is newer - a later
    revision, or a `format_version` from a client we do not understand. Nothing
    committed (chunks, MACs, metadata) can therefore regress, and the data
    itself is flushed first so the state never claims bytes that are not there.
    """
    from ..utils.filelock import FileLockError

    sp = state_path_for(state.destination)
    sp.parent.mkdir(parents=True, exist_ok=True)

    # Outside both locks: fsync can be slow and needs neither.
    _flush_transferred_data(state)

    data = asdict(state)
    # Convert int chunk_macs keys to strings for JSON
    data["chunk_macs"] = {str(k): v for k, v in state.chunk_macs.items()}
    payload = json.dumps(data, separators=(",", ":"))

    file_lock = _state_lock_for(sp)
    with _save_lock:
        try:
            file_lock.acquire(timeout=STATE_LOCK_TIMEOUT)
        except FileLockError as exc:
            # Losing resume progress is better than corrupting it, and the
            # transfer itself is unaffected.
            log.warning("Could not lock %s to save resume state: %s", sp.name, exc)
            return
        try:
            disk_version, disk_revision = _disk_guard(sp)
            if disk_version > STATE_FORMAT_VERSION:
                log.warning(
                    "Refusing to overwrite %s: it was written by a newer format version (%d).",
                    sp.name,
                    disk_version,
                )
                return
            if disk_revision > state.revision:
                log.debug(
                    "Discarding a stale resume snapshot for %s (revision %d < committed %d)",
                    sp.name,
                    state.revision,
                    disk_revision,
                )
                return
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=sp.parent, delete=False, suffix=".tmp"
            ) as tf:
                tf.write(payload)
                tf.flush()
                os.fsync(tf.fileno())
                temp_path = tf.name

            # `delete=False` means WE own this file until os.replace consumes
            # it. Every exit that is not a successful replace has to unlink it,
            # or a destination held open by antivirus quietly accumulates
            # `.mbstate.*.tmp` orphans beside the download. BaseException so an
            # interrupt mid-retry cleans up too; the original error always wins.
            try:
                # Windows: replace can transiently fail while the destination is
                # held open (previous replace, antivirus scan). Retry briefly.
                for attempt in range(5):
                    try:
                        os.replace(temp_path, sp)
                        return
                    except PermissionError:
                        if attempt == 4:
                            raise
                        time.sleep(0.05 * (attempt + 1))
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(temp_path)
                raise
        finally:
            file_lock.release()


def clear_state(destination: str | Path) -> None:
    """Remove the state file for a finished transfer, under the save lock.

    Unlinking outside the lock raced every writer: `save_state` can be between
    its read-verify and its `os.replace`, and the replace then RESURRECTS state
    for a transfer that just finished (or lost the file out from under it
    mid-write). The same two locks, in the same order, settle it.

    The `.lock` sidecar is deliberately NOT unlinked - see the long docstring
    on `utils/helpers.release_destination`: between `release()` and `unlink()`
    another process can lock the still-open inode while the unlink frees the
    NAME, so a third process locks a fresh inode and two owners believe they
    are exclusive. A leftover sidecar is empty, holds no lock once its owner
    exits, and the next transfer reuses it.
    """
    from ..utils.filelock import FileLockError

    sp = state_path_for(destination)
    file_lock = _state_lock_for(sp)
    with _save_lock:
        try:
            file_lock.acquire(timeout=STATE_LOCK_TIMEOUT)
        except FileLockError as exc:
            # Another live transfer owns this state. Deleting under it is worse
            # than leaving it: a stale file is re-validated on the next resume.
            log.warning("Could not lock %s to clear resume state: %s", sp.name, exc)
            return
        try:
            if _disk_guard(sp)[0] > STATE_FORMAT_VERSION:
                log.warning(
                    "Keeping %s: it was written by a newer format version.",
                    sp.name,
                )
                return
            with contextlib.suppress(FileNotFoundError):
                sp.unlink()
        finally:
            file_lock.release()
