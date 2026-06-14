"""Queue key recovery safety (Issue 3).

When encrypted queue secrets already exist, a missing/empty/corrupt key must
NOT be auto-replaced, and the queue file and key file must be preserved. Failed
recovery never deletes the queued item or its encrypted blob.
"""

import json
from pathlib import Path

import pytest

from megabasterd_cli.queue.manager import (
    JobType,
    QueueItem,
    QueueKeyError,
    QueueManager,
    QueueSecretBox,
)


def _mgr(tmp_path: Path, key_name: str = "queue.key") -> QueueManager:
    return QueueManager(tmp_path / "queue.json", secret_box=QueueSecretBox(tmp_path / key_name))


def _add_secret_item(tmp_path: Path, pw: str = "link-pw") -> str:
    q = _mgr(tmp_path)
    q.add(
        QueueItem(
            id="sec1",
            type=JobType.DOWNLOAD.value,
            source="https://mega.nz/file/X#Y",
            destination="",
            password=pw,
        )
    )
    return (tmp_path / "queue.json").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Safe creation when nothing depends on the key
# ---------------------------------------------------------------------------


def test_missing_key_empty_queue_creates_key(tmp_path: Path) -> None:
    q = _mgr(tmp_path)
    q.add(QueueItem(id="d", type=JobType.DOWNLOAD.value, source="u", destination="", password="p"))
    assert (tmp_path / "queue.key").exists()
    assert _mgr(tmp_path).items[0].password == "p"


def test_missing_key_only_nonsecret_items_ok(tmp_path: Path) -> None:
    q = _mgr(tmp_path)
    q.add(QueueItem(id="d", type=JobType.DOWNLOAD.value, source="u", destination=""))
    # No password -> no key needed; queue persists fine.
    assert not (tmp_path / "queue.key").exists()
    parsed = json.loads((tmp_path / "queue.json").read_text(encoding="utf-8"))
    assert parsed[0]["enc_password"] is None


# ---------------------------------------------------------------------------
# Refuse to orphan existing encrypted secrets
# ---------------------------------------------------------------------------


def test_missing_key_with_encrypted_secret_does_not_recreate(tmp_path: Path) -> None:
    original = _add_secret_item(tmp_path)
    # Remove the key, then reload: the secret becomes unrecoverable but is kept.
    (tmp_path / "queue.key").unlink()
    q2 = _mgr(tmp_path)
    assert q2.items[0].password is None
    # No key was created and the queue file is unchanged.
    assert not (tmp_path / "queue.key").exists()
    assert (tmp_path / "queue.json").read_text(encoding="utf-8") == original
    # Encrypted blob preserved verbatim.
    assert json.loads(original)[0]["enc_password"] == q2.items[0]._enc_password


def test_adding_secret_with_missing_key_and_existing_blob_refuses(tmp_path: Path) -> None:
    original = _add_secret_item(tmp_path)
    (tmp_path / "queue.key").unlink()
    q2 = _mgr(tmp_path)
    new_item = QueueItem(
        id="new", type=JobType.DOWNLOAD.value, source="u2", destination="", password="np"
    )
    with pytest.raises(QueueKeyError):
        q2.add(new_item)
    # Original queue file untouched (atomic save never replaced it).
    assert (tmp_path / "queue.json").read_text(encoding="utf-8") == original
    assert not (tmp_path / "queue.key").exists()


def test_empty_key_with_encrypted_secret_not_replaced(tmp_path: Path) -> None:
    original = _add_secret_item(tmp_path)
    (tmp_path / "queue.key").write_bytes(b"")  # truncated/partial
    q2 = _mgr(tmp_path)
    assert q2.items[0].password is None
    # Empty key file left as-is (not overwritten with a fresh 32-byte key).
    assert (tmp_path / "queue.key").read_bytes() == b""
    assert (tmp_path / "queue.json").read_text(encoding="utf-8") == original


def test_corrupt_key_with_encrypted_secret_not_replaced(tmp_path: Path) -> None:
    original = _add_secret_item(tmp_path)
    (tmp_path / "queue.key").write_bytes(b"x" * 10)  # wrong length
    q2 = _mgr(tmp_path)
    assert q2.items[0].password is None  # decrypt raised QueueKeyError, caught
    assert (tmp_path / "queue.key").read_bytes() == b"x" * 10  # unchanged
    assert (tmp_path / "queue.json").read_text(encoding="utf-8") == original


def test_wrong_key_preserves_blob(tmp_path: Path) -> None:
    original = _add_secret_item(tmp_path)
    # Replace the key with a different valid 32-byte key.
    import os

    (tmp_path / "queue.key").write_bytes(os.urandom(32))
    q2 = _mgr(tmp_path)
    assert q2.items[0].password is None
    q2.save()
    after = (tmp_path / "queue.json").read_text(encoding="utf-8")
    assert json.loads(after)[0]["enc_password"] == json.loads(original)[0]["enc_password"]


# ---------------------------------------------------------------------------
# Migration safety
# ---------------------------------------------------------------------------


def test_legacy_migration_with_no_existing_blob(tmp_path: Path) -> None:
    legacy = [
        {
            "id": "l",
            "type": "download",
            "source": "u",
            "destination": "",
            "password": "legacy-pw",
        }
    ]
    (tmp_path / "queue.json").write_text(json.dumps(legacy), encoding="utf-8")
    q = _mgr(tmp_path)
    assert q.items[0].password == "legacy-pw"
    raw = (tmp_path / "queue.json").read_text(encoding="utf-8")
    assert "legacy-pw" not in raw
    assert json.loads(raw)[0]["enc_password"]


def test_malformed_queue_not_rewritten_and_no_key(tmp_path: Path) -> None:
    (tmp_path / "queue.json").write_text("{ this is not json", encoding="utf-8")
    _mgr(tmp_path)
    assert (tmp_path / "queue.json").read_text(encoding="utf-8") == "{ this is not json"
    assert not (tmp_path / "queue.key").exists()


def test_no_secret_in_logs_on_recovery_failure(tmp_path: Path, caplog) -> None:
    import logging

    _add_secret_item(tmp_path, pw="topsecretpw")
    (tmp_path / "queue.key").unlink()
    with caplog.at_level(logging.DEBUG, logger="megabasterd_cli.queue.manager"):
        _mgr(tmp_path)
    assert "topsecretpw" not in caplog.text
