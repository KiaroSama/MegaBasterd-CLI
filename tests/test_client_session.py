import json
from pathlib import Path

import pytest

from megabasterd_cli.core.client import MegaClient, MegaSession
from megabasterd_cli.core.errors import AuthError


def _client_with_session() -> MegaClient:
    client = MegaClient()
    client.session = MegaSession(
        sid="session-id",
        master_key=b"\x01" * 16,
        rsa_private_key=b"\x02" * 8,
        user_handle="user-handle",
        email="user@example.com",
    )
    return client


def test_save_session_requires_passphrase(tmp_path: Path):
    client = _client_with_session()

    with pytest.raises(AuthError):
        client.save_session(tmp_path / "session.json")


def test_session_roundtrip_is_encrypted(tmp_path: Path):
    path = tmp_path / "session.json"
    client = _client_with_session()

    client.save_session(path, passphrase="secret")
    raw = path.read_text(encoding="utf-8")

    assert "master_key" not in raw
    assert "session-id" not in raw
    assert MegaClient.load_session(path) is None
    assert MegaClient.load_session(path, passphrase="wrong") is None

    loaded = MegaClient.load_session(path, passphrase="secret")

    assert loaded is not None
    assert loaded.sid == "session-id"
    assert loaded.master_key == b"\x01" * 16
    assert loaded.rsa_private_key == b"\x02" * 8


def test_load_session_rejects_unsupported_encrypted_version(tmp_path: Path):
    path = tmp_path / "session.json"
    path.write_text(json.dumps({"version": 99, "encrypted": "unused"}), encoding="utf-8")

    assert MegaClient.load_session(path, passphrase="secret") is None


def test_decode_session_id_rejects_too_short_plaintext():
    def part(value: int) -> bytes:
        raw = value.to_bytes(1, "big")
        return (8).to_bytes(2, "big") + raw

    rsa_blob = part(3) + part(5) + part(1) + part(1)

    with pytest.raises(AuthError, match="Malformed encrypted session ID"):
        MegaClient()._decode_session_id(b"\x01", rsa_blob)
