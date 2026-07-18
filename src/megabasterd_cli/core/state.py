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
_VALID_TRANSFER_TYPES = frozenset({"download", "upload"})


class StateCorruptionError(Exception):
    """A `.mbstate` file is unusable: malformed, mistyped, or inconsistent."""


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
    _require(isinstance(metadata, dict), "state field 'metadata' must be an object")

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
    }
    return {
        **{k: v for k, v in data.items() if k in known},
        "format_version": version,
        "completed_chunks": list(chunks),
        "chunk_macs": normalized,
        "metadata": metadata,
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

    @property
    def completed_set(self) -> set[int]:
        return set(self.completed_chunks)

    def is_chunk_done(self, index: int) -> bool:
        return index in self.completed_set

    def mark_chunk_done(self, index: int, mac: bytes | None = None) -> None:
        if index not in self.completed_set:
            self.completed_chunks.append(index)
        if mac is not None:
            self.chunk_macs[index] = mac.hex()

    def get_chunk_mac(self, index: int) -> bytes | None:
        hex_mac = self.chunk_macs.get(index)
        return bytes.fromhex(hex_mac) if hex_mac else None


def snapshot_state(state: TransferState) -> TransferState:
    """Return a shallow immutable-enough copy for serialization outside locks."""
    return TransferState(
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
    """Preserve a corrupt `.mbstate` before the transfer restarts over it."""
    from ..utils.corruption import preserve_corrupt_file

    log.warning("Ignoring corrupt transfer state %s: %s", state_path.name, reason)
    preserve_corrupt_file(state_path, data)


def save_state(state: TransferState) -> None:
    """Atomically save the state file.

    Two locks, two different races: the in-process mutex serializes this
    process's chunk workers, and the advisory FILE lock serializes independent
    CLI processes so a second process cannot interleave its own
    write-then-replace and lose committed chunks. Serialization happens before
    either lock is taken, so a serialization failure leaves the original file
    untouched and drops no temp file.
    """
    from ..utils.filelock import FileLockError

    sp = state_path_for(state.destination)
    sp.parent.mkdir(parents=True, exist_ok=True)

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
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=sp.parent, delete=False, suffix=".tmp"
            ) as tf:
                tf.write(payload)
                tf.flush()
                os.fsync(tf.fileno())
                temp_path = tf.name

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
        finally:
            file_lock.release()


def clear_state(destination: str | Path) -> None:
    """Remove the state file (and its lock sidecar) for a finished transfer."""
    sp = state_path_for(destination)
    with contextlib.suppress(FileNotFoundError):
        sp.unlink()
    # Leave no lock sidecar behind. On Windows this can fail while another
    # process still holds it; that is harmless and the file is reused.
    with contextlib.suppress(OSError):
        (sp.parent / (sp.name + ".lock")).unlink()
