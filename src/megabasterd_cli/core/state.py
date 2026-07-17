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

# Serializes concurrent saves from parallel chunk workers; on Windows two
# simultaneous os.replace() calls onto the same target (or a virus scanner
# holding the fresh file) raise PermissionError.
_save_lock = threading.Lock()


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
    """Load existing state for a destination, or None if no state file exists."""
    sp = state_path_for(destination)
    if not sp.exists():
        return None
    try:
        with open(sp, encoding="utf-8") as f:
            data = json.load(f)
        # The completed_chunks JSON list may have string keys for chunk_macs
        # because JSON object keys are strings.
        macs = data.get("chunk_macs", {})
        data["chunk_macs"] = {int(k): v for k, v in macs.items()}
        data.setdefault("format_version", STATE_FORMAT_VERSION)
        if data["format_version"] != STATE_FORMAT_VERSION:
            log.debug(
                "Ignoring unsupported transfer state version %s in %s",
                data["format_version"],
                sp,
            )
            return None
        return TransferState(**data)
    except (json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
        log.debug("Ignoring unreadable transfer state %s: %s", sp, exc)
        return None


def save_state(state: TransferState) -> None:
    """Atomically save the state file."""
    sp = state_path_for(state.destination)
    sp.parent.mkdir(parents=True, exist_ok=True)

    data = asdict(state)
    # Convert int chunk_macs keys to strings for JSON
    data["chunk_macs"] = {str(k): v for k, v in state.chunk_macs.items()}

    with _save_lock:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=sp.parent, delete=False, suffix=".tmp"
        ) as tf:
            json.dump(data, tf, separators=(",", ":"))
            temp_path = tf.name

        # Windows: replace can transiently fail while the destination is held
        # open (previous replace, antivirus scan). Retry briefly.
        for attempt in range(5):
            try:
                os.replace(temp_path, sp)
                return
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.05 * (attempt + 1))


def clear_state(destination: str | Path) -> None:
    """Remove the state file for a completed transfer."""
    sp = state_path_for(destination)
    with contextlib.suppress(FileNotFoundError):
        sp.unlink()
