"""Shape/type validation for raw queue entries read from disk.

Every shape/type/enum failure becomes QueueCorruptionError, so a raw
TypeError/ValueError/KeyError from the dataclass constructor can never escape
to the CLI.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt

from .errors import QueueCorruptionError
from .models import _TERMINAL_STATUSES, JobStatus, JobType

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


def validate_raw_item(entry) -> dict:
    """Validate one raw queue entry's shape; raise QueueCorruptionError."""
    if not isinstance(entry, dict):
        raise QueueCorruptionError(f"queue entry is {type(entry).__name__}, expected an object")
    for name, expected in _REQUIRED_ITEM_FIELDS.items():
        if name not in entry:
            raise QueueCorruptionError(f"queue entry is missing required field {name!r}")
        if not isinstance(entry[name], expected):
            raise QueueCorruptionError(f"queue entry field {name!r} must be {expected.__name__}")
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
    # Legacy files predate the lease generation; absent means 0. Unlike
    # run_id/heartbeat_iso it is NOT cleared on a terminal status: it is a
    # monotonic counter, so an old owner stays locked out forever.
    epoch = entry.get("lease_epoch", 0)
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        raise QueueCorruptionError("queue entry field 'lease_epoch' must be an integer >= 0")
    for name in _OPTIONAL_STR_ITEM_FIELDS:
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


def validate_unique_ids(entries: list[dict]) -> None:
    """Job ids address jobs: `remove`/`retry`/`update_status` would act on
    an arbitrary one of a duplicated pair, so duplicates are corruption."""
    seen: set[str] = set()
    for entry in entries:
        item_id = entry["id"]
        if item_id in seen:
            raise QueueCorruptionError(f"queue contains duplicate job id {item_id!r}")
        seen.add(item_id)
