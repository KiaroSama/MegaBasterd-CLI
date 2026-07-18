"""Complete queue schema validation.

Every shape/type/enum violation must become QueueCorruptionError — never a raw
TypeError/ValueError/KeyError from `in` or the dataclass constructor — and the
original file must survive untouched with exactly one backup.
"""

from __future__ import annotations

import json

import pytest

from megabasterd_cli.queue.manager import QueueCorruptionError, QueueItem, QueueManager


def _valid(**overrides) -> dict:
    entry = {
        "id": "abc123",
        "type": "download",
        "source": "https://mega.nz/file/ID#<key>",
        "destination": "/tmp/out",
        "size": 10,
        "status": "pending",
        "created_iso": "2026-01-01T00:00:00+00:00",
    }
    entry.update(overrides)
    return entry


def _manager(tmp_path, payload) -> QueueManager:
    path = tmp_path / "queue.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return QueueManager(path=path, lock_timeout=0.5)


BAD_ENTRIES = {
    "missing-status": {**_valid(), "status": None},
    "unknown-status": _valid(status="sideways"),
    "list-status": _valid(status=["pending"]),
    "dict-status": _valid(status={"v": "pending"}),
    "list-type": _valid(type=["download"]),
    "dict-type": _valid(type={"v": "download"}),
    "number-type": _valid(type=3),
    "unknown-type": _valid(type="teleport"),
    "bool-size": _valid(size=True),
    "negative-size": _valid(size=-1),
    "string-size": _valid(size="10"),
    "float-size": _valid(size=1.5),
    "empty-id": _valid(id=""),
    "blank-id": _valid(id="   "),
    "int-id": _valid(id=42),
    "bad-run-id": _valid(run_id=17),
    "bad-heartbeat": _valid(heartbeat_iso=["now"]),
    "bad-finished": _valid(finished_iso={"at": "now"}),
    "bad-error": _valid(error=500),
    "bad-account": _valid(account=[]),
    "bad-password": _valid(password=1234),
    "bad-enc-password": _valid(enc_password=99),
    "bad-created": _valid(created_iso=20260101),
    "missing-required": {"id": "x", "type": "download", "source": "s"},
    "not-an-object": "just a string",
}


@pytest.mark.parametrize("bad", BAD_ENTRIES.values(), ids=list(BAD_ENTRIES))
def test_invalid_entry_is_corruption_not_a_raw_exception(tmp_path, bad):
    raw = json.dumps([bad]).encode("utf-8")
    path = tmp_path / "queue.json"
    path.write_bytes(raw)
    mgr = QueueManager(path=path, lock_timeout=0.5)
    assert mgr.is_corrupt, f"{bad!r} must be rejected"
    with pytest.raises(QueueCorruptionError):
        mgr.add(QueueItem(id="new", type="download", source="s", destination="d"))
    assert path.read_bytes() == raw, "the original queue must be preserved byte-for-byte"
    backups = list(tmp_path.glob("queue.json.corrupt.*"))
    assert len(backups) == 1 and backups[0].read_bytes() == raw


def test_mixed_valid_and_invalid_loads_nothing(tmp_path):
    raw = json.dumps([_valid(), _valid(id="second", size=True)]).encode("utf-8")
    path = tmp_path / "queue.json"
    path.write_bytes(raw)
    mgr = QueueManager(path=path, lock_timeout=0.5)
    assert mgr.is_corrupt
    assert mgr.items == [], "never partially load a mixed valid/invalid queue"
    assert path.read_bytes() == raw


def test_valid_entries_still_load(tmp_path):
    mgr = _manager(tmp_path, [_valid(), _valid(id="two", status="done", size=0)])
    assert not mgr.is_corrupt
    assert [i.id for i in mgr.items] == ["abc123", "two"]


def test_optional_nulls_are_accepted(tmp_path):
    mgr = _manager(
        tmp_path,
        [
            _valid(
                run_id=None,
                heartbeat_iso=None,
                finished_iso=None,
                error=None,
                account=None,
                password=None,
                enc_password=None,
            )
        ],
    )
    assert not mgr.is_corrupt and len(mgr.items) == 1


def test_legacy_plaintext_password_is_migrated_to_an_encrypted_blob(tmp_path):
    mgr = _manager(tmp_path, [_valid(password="link-pass")])
    assert not mgr.is_corrupt
    assert mgr.items[0].password == "link-pass"
    on_disk = json.loads((tmp_path / "queue.json").read_text(encoding="utf-8"))[0]
    assert "password" not in on_disk, "plaintext must not survive the migration"
    assert on_disk["enc_password"], "the secret must be re-sealed"


def test_reset_recovers_a_corrupt_queue_and_keeps_the_backup(tmp_path):
    raw = json.dumps([_valid(size=True)]).encode("utf-8")
    path = tmp_path / "queue.json"
    path.write_bytes(raw)
    mgr = QueueManager(path=path, lock_timeout=0.5)
    mgr.reset()
    assert not mgr.is_corrupt
    assert json.loads(path.read_text(encoding="utf-8")) == []
    backups = list(tmp_path.glob("queue.json.corrupt.*"))
    assert len(backups) == 1 and backups[0].read_bytes() == raw


# ---------------------------------------------------------------------------
# Semantic completeness: shapes that are structurally fine but operationally
# ambiguous. These all loaded silently before.
# ---------------------------------------------------------------------------


def test_duplicate_ids_are_rejected(tmp_path):
    raw = json.dumps([_valid(), _valid()]).encode("utf-8")
    path = tmp_path / "queue.json"
    path.write_bytes(raw)
    mgr = QueueManager(path=path, lock_timeout=0.5)
    assert mgr.is_corrupt, "an id addresses a job; duplicates make remove/retry ambiguous"
    assert mgr.items == []
    assert path.read_bytes() == raw


def test_distinct_ids_still_load(tmp_path):
    mgr = _manager(tmp_path, [_valid(id="one"), _valid(id="two")])
    assert not mgr.is_corrupt and len(mgr.items) == 2


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_blank_source_is_rejected(tmp_path, blank):
    mgr = _manager(tmp_path, [_valid(source=blank)])
    assert mgr.is_corrupt


def test_empty_destination_is_accepted_as_documented(tmp_path):
    """Upload jobs are written with destination="" and the runner falls back to
    config download_path, so this must NOT be treated as corruption."""
    mgr = _manager(tmp_path, [_valid(destination="")])
    assert not mgr.is_corrupt and len(mgr.items) == 1


@pytest.mark.parametrize(
    "stamp",
    [
        "2026-01-01T00:00:00",  # naive: no timezone
        "not-a-date",
        "2026-13-45T99:99:99+00:00",
        "01/01/2026",
    ],
)
def test_invalid_created_iso_is_rejected(tmp_path, stamp):
    mgr = _manager(tmp_path, [_valid(created_iso=stamp)])
    assert mgr.is_corrupt, f"{stamp!r} must be rejected"


def test_legacy_empty_created_iso_is_still_accepted(tmp_path):
    """Documented legacy value: files predating created_iso carry ""."""
    mgr = _manager(tmp_path, [_valid(created_iso="")])
    assert not mgr.is_corrupt and len(mgr.items) == 1


def test_utc_z_suffix_timestamp_is_accepted(tmp_path):
    mgr = _manager(tmp_path, [_valid(created_iso="2026-01-01T00:00:00Z")])
    assert not mgr.is_corrupt


@pytest.mark.parametrize("field_name", ["finished_iso", "heartbeat_iso"])
def test_invalid_optional_timestamps_are_rejected(tmp_path, field_name):
    entry = _valid(status="done") if field_name == "finished_iso" else _valid(status="active")
    entry[field_name] = "whenever"
    mgr = _manager(tmp_path, [entry])
    assert mgr.is_corrupt


@pytest.mark.parametrize("status", ["pending", "done", "failed", "canceled", "interrupted"])
def test_lease_fields_on_a_non_active_status_are_rejected(tmp_path, status):
    """Every writer clears run_id/heartbeat off a non-active job, so their
    presence means the file was edited or damaged."""
    entry = _valid(status=status, run_id="run-1")
    if status in ("done", "failed", "canceled"):
        entry["finished_iso"] = "2026-01-02T00:00:00+00:00"
    mgr = _manager(tmp_path, [entry])
    assert mgr.is_corrupt


def test_active_job_without_a_lease_is_accepted(tmp_path):
    """The crashed-owner / legacy shape recover_interrupted() exists to fix."""
    mgr = _manager(tmp_path, [_valid(status="active")])
    assert not mgr.is_corrupt and len(mgr.items) == 1


def test_finished_iso_on_a_running_status_is_rejected(tmp_path):
    mgr = _manager(tmp_path, [_valid(status="pending", finished_iso="2026-01-02T00:00:00+00:00")])
    assert mgr.is_corrupt


def test_invalid_enc_password_encoding_is_rejected(tmp_path):
    mgr = _manager(tmp_path, [_valid(enc_password="!!! not base64 !!!")])
    assert mgr.is_corrupt


def test_unknown_fields_are_preserved_not_dropped(tmp_path):
    """Forward compatibility: a field written by a newer version survives a
    load/save round trip instead of being silently discarded."""
    path = tmp_path / "queue.json"
    path.write_text(json.dumps([_valid(future_field={"nested": 1})]), encoding="utf-8")
    mgr = QueueManager(path=path, lock_timeout=0.5)
    assert not mgr.is_corrupt
    mgr.save()
    on_disk = json.loads(path.read_text(encoding="utf-8"))[0]
    assert on_disk["future_field"] == {"nested": 1}


def test_no_raw_exception_escapes_for_any_semantic_violation(tmp_path):
    """Whatever the violation, the CLI sees QueueCorruptionError only."""
    bad_entries = [
        _valid(created_iso="nope"),
        _valid(status="done", run_id="r"),
        _valid(source="  "),
        _valid(enc_password="%%%"),
    ]
    for entry in bad_entries:
        path = tmp_path / "queue.json"
        path.write_text(json.dumps([entry]), encoding="utf-8")
        mgr = QueueManager(path=path, lock_timeout=0.5)
        with pytest.raises(QueueCorruptionError):
            mgr.add(QueueItem(id="new", type="download", source="s", destination="d"))
