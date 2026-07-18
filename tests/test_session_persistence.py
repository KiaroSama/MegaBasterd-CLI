"""`load_session` really returns None on corrupt input, and `save_session` is atomic.

Two defects:

* The documented contract is "returns None if the file is missing/corrupt", but
  the except tuple was (JSONDecodeError, KeyError, ValueError, OSError,
  InvalidTag). A JSON file holding the bare string `"encrypted"` passes the
  `"encrypted" in data` substring test and then raises AttributeError on
  `data.get`; `123` and `null` raise TypeError on the `in` test itself. Neither
  is in the tuple, so the exception escaped to the CLI catch-all.
* `save_session` truncated the target with `open(path, "w")` before writing and
  chmod'ed to 0o600 only AFTER the write - so a failure mid-write destroyed the
  previous session, and the SID was briefly world-readable on disk.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from megabasterd_cli.core.client import MegaClient, MegaSession


def _client() -> MegaClient:
    client = MegaClient()
    client.session = MegaSession(
        sid="session-id",
        master_key=b"\x01" * 16,
        rsa_private_key=b"\x02" * 8,
        user_handle="user-handle",
        email="user@example.com",
    )
    return client


# ---------------------------------------------------------------------------
# load_session: "corrupt" means every kind of corrupt.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param('"encrypted"', id="bare_string_containing_the_marker"),
        pytest.param('["encrypted"]', id="list_containing_the_marker"),
        pytest.param("123", id="bare_int"),
        pytest.param("null", id="bare_null"),
        pytest.param("true", id="bare_bool"),
        pytest.param('"anything"', id="bare_string"),
        pytest.param("[]", id="empty_list"),
        pytest.param('{"version": 2, "encrypted": 42}', id="encrypted_blob_is_not_a_string"),
        pytest.param("not json at all", id="not_json"),
    ],
)
def test_load_session_returns_none_for_any_corrupt_file(tmp_path: Path, raw: str):
    path = tmp_path / "session.json"
    path.write_text(raw, encoding="utf-8")

    assert MegaClient.load_session(path, passphrase="secret") is None


def test_load_session_rejects_a_decrypted_payload_that_is_not_an_object(tmp_path: Path):
    from megabasterd_cli.accounts.storage import CredentialVault

    path = tmp_path / "session.json"
    path.write_text(
        json.dumps(
            {"version": 2, "encrypted": CredentialVault("secret").encrypt(json.dumps([1, 2, 3]))}
        ),
        encoding="utf-8",
    )

    assert MegaClient.load_session(path, passphrase="secret") is None


def test_a_future_version_is_refused_without_destroying_the_file(tmp_path: Path):
    """Unchanged behaviour: a newer client's file survives an older client."""
    path = tmp_path / "session.json"
    original = json.dumps({"version": 99, "encrypted": "unused"})
    path.write_text(original, encoding="utf-8")

    assert MegaClient.load_session(path, passphrase="secret") is None
    assert path.read_text(encoding="utf-8") == original


# ---------------------------------------------------------------------------
# save_session: atomic, and owner-only from creation.
# ---------------------------------------------------------------------------


def test_a_failed_save_leaves_the_previous_session_intact(tmp_path: Path, monkeypatch):
    path = tmp_path / "session.json"
    _client().save_session(path, passphrase="secret")
    before = path.read_bytes()

    def explode(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", explode)
    with pytest.raises(OSError):
        _client().save_session(path, passphrase="secret")

    assert path.read_bytes() == before, "the previous session was destroyed by a failed write"
    assert MegaClient.load_session(path, passphrase="secret") is not None


def test_a_failed_save_leaves_no_temporary_files_behind(tmp_path: Path, monkeypatch):
    path = tmp_path / "session.json"

    def explode(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", explode)
    with pytest.raises(OSError):
        _client().save_session(path, passphrase="secret")

    assert list(tmp_path.iterdir()) == [], "a partial session file was left on disk"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits only")
def test_the_session_file_is_owner_only(tmp_path: Path):
    path = tmp_path / "session.json"
    _client().save_session(path, passphrase="secret")

    assert path.stat().st_mode & 0o777 == 0o600


def test_the_roundtrip_still_works(tmp_path: Path):
    path = tmp_path / "nested" / "session.json"
    _client().save_session(path, passphrase="secret")

    loaded = MegaClient.load_session(path, passphrase="secret")

    assert loaded is not None
    assert loaded.sid == "session-id"
    assert loaded.master_key == b"\x01" * 16
    assert loaded.rsa_private_key == b"\x02" * 8
