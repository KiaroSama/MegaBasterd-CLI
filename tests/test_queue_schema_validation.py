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
