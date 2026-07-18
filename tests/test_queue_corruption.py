"""MF6 + MF7: corrupt-queue preservation and schema validation."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from megabasterd_cli.queue.manager import (
    JobStatus,
    JobType,
    QueueCorruptionError,
    QueueItem,
    QueueManager,
)


def _mgr(tmp_path):
    return QueueManager(tmp_path / "queue.json")


def _write(tmp_path, content: bytes):
    (tmp_path / "queue.json").write_bytes(content)


def _add_ok(tmp_path):
    q = _mgr(tmp_path)
    q.add(QueueItem(id=QueueItem.new_id(), type=JobType.DOWNLOAD.value, source="u", destination=""))
    return q


def test_malformed_json_is_preserved_and_blocks_mutation(tmp_path):
    _write(tmp_path, b"{ this is not json ")
    original = (tmp_path / "queue.json").read_bytes()
    q = _mgr(tmp_path)
    assert q.is_corrupt
    with pytest.raises(QueueCorruptionError):
        q.add(QueueItem(id="x", type=JobType.DOWNLOAD.value, source="u", destination=""))
    # Byte-for-byte preserved; a backup exists.
    assert (tmp_path / "queue.json").read_bytes() == original
    backups = list(tmp_path.glob("queue.json.corrupt.*"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == original


def test_backup_created_once_not_on_every_read(tmp_path):
    _write(tmp_path, b"not json")
    _mgr(tmp_path)
    _mgr(tmp_path)
    _mgr(tmp_path)
    assert len(list(tmp_path.glob("queue.json.corrupt.*"))) == 1


def test_non_list_root_is_corruption(tmp_path):
    _write(tmp_path, json.dumps({"not": "a list"}).encode())
    q = _mgr(tmp_path)
    assert q.is_corrupt


def test_string_root_is_corruption(tmp_path):
    _write(tmp_path, json.dumps("just a string").encode())
    assert _mgr(tmp_path).is_corrupt


def test_list_of_non_objects_is_corruption(tmp_path):
    _write(tmp_path, json.dumps(["a string", 5, None]).encode())
    assert _mgr(tmp_path).is_corrupt


def test_missing_required_field_is_corruption(tmp_path):
    _write(tmp_path, json.dumps([{"id": "x", "type": "download"}]).encode())  # no source/dest
    assert _mgr(tmp_path).is_corrupt


def test_invalid_status_is_corruption(tmp_path):
    entry = {"id": "x", "type": "download", "source": "u", "destination": "", "status": "weird"}
    _write(tmp_path, json.dumps([entry]).encode())
    assert _mgr(tmp_path).is_corrupt


def test_invalid_type_is_corruption(tmp_path):
    entry = {"id": "x", "type": "teleport", "source": "u", "destination": ""}
    _write(tmp_path, json.dumps([entry]).encode())
    assert _mgr(tmp_path).is_corrupt


def test_invalid_numeric_type_is_corruption(tmp_path):
    entry = {"id": "x", "type": "download", "source": "u", "destination": "", "size": "big"}
    _write(tmp_path, json.dumps([entry]).encode())
    assert _mgr(tmp_path).is_corrupt


def test_valid_queue_still_loads(tmp_path):
    _add_ok(tmp_path)
    reloaded = _mgr(tmp_path)
    assert not reloaded.is_corrupt
    assert len(reloaded.items) == 1


def test_reset_recovers_and_allows_mutation(tmp_path):
    _write(tmp_path, b"garbage")
    q = _mgr(tmp_path)
    assert q.is_corrupt
    q.reset()
    assert not q.is_corrupt
    q.add(QueueItem(id="y", type=JobType.DOWNLOAD.value, source="u", destination=""))
    fresh = _mgr(tmp_path)
    assert not fresh.is_corrupt
    assert len(fresh.items) == 1


def test_encrypted_blobs_preserved_verbatim_in_backup(tmp_path):
    # Build a valid queue with an encrypted secret, then corrupt the file by
    # appending garbage, and confirm the backup keeps the enc_password intact.
    q = _mgr(tmp_path)
    q.add(
        QueueItem(
            id=QueueItem.new_id(),
            type=JobType.DOWNLOAD.value,
            source="u",
            destination="",
            password="link-secret",
        )
    )
    good = json.loads((tmp_path / "queue.json").read_text(encoding="utf-8"))
    assert good[0].get("enc_password")
    corrupt = (tmp_path / "queue.json").read_bytes() + b"\n<<garbage>>"
    (tmp_path / "queue.json").write_bytes(corrupt)
    _mgr(tmp_path)
    backup = next(tmp_path.glob("queue.json.corrupt.*"))
    assert backup.read_bytes() == corrupt


def test_no_queue_key_created_while_corrupt(tmp_path):
    _write(tmp_path, b"not json")
    _mgr(tmp_path)
    assert not (tmp_path / "queue.key").exists(), "no key may be created over a corrupt queue"


_SUB = r"""
import sys
from pathlib import Path
from megabasterd_cli.queue.manager import QueueManager
q = QueueManager(Path(sys.argv[1]) / "queue.json")
print("corrupt" if q.is_corrupt else "ok")
"""


def test_concurrent_processes_do_not_duplicate_backups(tmp_path):
    _write(tmp_path, b"still not json")
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _SUB, str(tmp_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(3)
    ]
    for p in procs:
        out, err = p.communicate(timeout=60)
        assert p.returncode == 0, err
        assert out.strip() == "corrupt"
    assert len(list(tmp_path.glob("queue.json.corrupt.*"))) == 1


def test_corrupt_queue_run_exits_nonzero(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from megabasterd_cli.cli import cli

    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))
    from megabasterd_cli.config import data_dir

    data_dir().mkdir(parents=True, exist_ok=True)
    (data_dir() / "queue.json").write_bytes(b"not json at all")
    result = CliRunner().invoke(cli, ["-q", "queue", "run"])
    assert result.exit_code == 1
    result2 = CliRunner().invoke(cli, ["-q", "queue", "add-download", "https://mega.nz/file/a#b"])
    assert result2.exit_code == 1

    assert JobStatus.PENDING  # symbol used
