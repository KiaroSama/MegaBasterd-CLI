"""Regression tests for queued password protection at rest (Priority 5)."""

import json
from pathlib import Path

from megabasterd_cli.queue.manager import (
    JobType,
    QueueItem,
    QueueManager,
    QueueSecretBox,
)


def _mgr(tmp_path: Path, key_name: str = "queue.key") -> QueueManager:
    return QueueManager(
        tmp_path / "queue.json",
        secret_box=QueueSecretBox(tmp_path / key_name),
    )


def test_password_not_persisted_in_plaintext(tmp_path: Path) -> None:
    q = _mgr(tmp_path)
    q.add(
        QueueItem(
            id=QueueItem.new_id(),
            type=JobType.DOWNLOAD.value,
            source="https://mega.nz/file/X#Y",
            destination="",
            password="super-secret-link-pw",
        )
    )
    raw = (tmp_path / "queue.json").read_text(encoding="utf-8")
    assert "super-secret-link-pw" not in raw
    parsed = json.loads(raw)
    assert "password" not in parsed[0]
    assert parsed[0]["enc_password"]


def test_password_recovered_on_reload(tmp_path: Path) -> None:
    q = _mgr(tmp_path)
    q.add(
        QueueItem(
            id="abc123",
            type=JobType.DOWNLOAD.value,
            source="https://mega.nz/file/X#Y",
            destination="",
            password="recover-me",
        )
    )
    reloaded = _mgr(tmp_path)
    assert reloaded.items[0].password == "recover-me"


def test_no_password_yields_null_enc(tmp_path: Path) -> None:
    q = _mgr(tmp_path)
    q.add(
        QueueItem(
            id="no-pw",
            type=JobType.DOWNLOAD.value,
            source="https://mega.nz/file/X#Y",
            destination="",
        )
    )
    parsed = json.loads((tmp_path / "queue.json").read_text(encoding="utf-8"))
    assert parsed[0]["enc_password"] is None
    assert "password" not in parsed[0]


def test_legacy_plaintext_password_is_migrated(tmp_path: Path) -> None:
    legacy = [
        {
            "id": "legacy1",
            "type": "download",
            "source": "https://mega.nz/file/X#Y",
            "destination": "",
            "size": 0,
            "status": "pending",
            "error": None,
            "account": None,
            "password": "legacy-plaintext",
            "created_iso": "",
            "finished_iso": None,
        }
    ]
    (tmp_path / "queue.json").write_text(json.dumps(legacy), encoding="utf-8")

    q = _mgr(tmp_path)
    # In-memory password is preserved...
    assert q.items[0].password == "legacy-plaintext"
    # ...and the file was rewritten without plaintext.
    raw = (tmp_path / "queue.json").read_text(encoding="utf-8")
    assert "legacy-plaintext" not in raw
    assert json.loads(raw)[0]["enc_password"]


def test_unrecoverable_secret_is_not_dropped(tmp_path: Path) -> None:
    q = _mgr(tmp_path, key_name="key_a")
    q.add(
        QueueItem(
            id="x",
            type=JobType.DOWNLOAD.value,
            source="s",
            destination="",
            password="cant-touch-this",
        )
    )
    original = json.loads((tmp_path / "queue.json").read_text(encoding="utf-8"))[0]["enc_password"]

    # Open with a different key -> cannot decrypt.
    q2 = _mgr(tmp_path, key_name="key_b")
    assert q2.items[0].password is None
    # Saving must preserve the original token, not discard the secret.
    q2.save()
    after = json.loads((tmp_path / "queue.json").read_text(encoding="utf-8"))[0]["enc_password"]
    assert after == original


def test_repr_does_not_leak_password(tmp_path: Path) -> None:
    item = QueueItem(
        id="r",
        type=JobType.DOWNLOAD.value,
        source="s",
        destination="",
        password="leaky",
    )
    assert "leaky" not in repr(item)
