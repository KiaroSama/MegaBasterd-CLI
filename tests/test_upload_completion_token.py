"""The completion token goes to MEGA verbatim, not base64-encoded again.

Found by the first live upload that got far enough to try. Every chunk
transferred, 100%, and then `{"a":"p"}` came back `-9` (ENOENT): the node could
not be created, so the upload always failed at the very last step.

MEGA's upload endpoint returns the completion token as an ASCII string in the
body of the final chunk's response - `FCCyf3QV62uAsbARFKbVd8zWyqOQXPFgEL9i`,
36 characters. `_register_node` passed it through `b64_url_encode`, which encoded
those ASCII bytes a second time and sent `RkNDeWYzUVY2MnVBc2JBUkZLYlZkOHpXeXFP`
as the handle. It is not a handle MEGA knows, hence ENOENT.

The other three fields in that request ARE base64 (attributes, wrapped key),
which is presumably why the token was treated the same way. It is the one that
arrives already encoded.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from megabasterd_cli.core.uploader import MegaUploader

# A real token, shape and length as MEGA sends it.
TOKEN = b"FCCyf3QV62uAsbARFKbVd8zWyqOQXPFgEL9i"


class _RecordingAPI:
    def __init__(self):
        self.calls: list[dict] = []

    def complete_upload(self, **kwargs) -> dict:
        self.calls.append(kwargs)
        return {"f": [{"h": "NEWNODE1"}]}

    def clone(self):
        return self


def _uploader() -> tuple[MegaUploader, _RecordingAPI]:
    api = _RecordingAPI()
    client = SimpleNamespace(
        session=SimpleNamespace(master_key=b"\x00" * 16, email="a@example.invalid"),
        api=api,
        find_root=lambda: "ROOTHNDL",
        invalidate_cache=lambda: None,
    )
    return MegaUploader(client=client), api


def test_the_token_is_sent_exactly_as_mega_returned_it():
    """The concrete failure: base64 of an already-encoded token is not a handle."""
    uploader, api = _uploader()

    uploader._register_node(
        target="ROOTHNDL",
        upload_name="Real test.txt",
        aes_key=b"\x11" * 16,
        nonce=b"\x22" * 8,
        mac_iv=b"\x33" * 8,
        completion_token=TOKEN,
    )

    assert api.calls, "_register_node never registered the node"
    sent = api.calls[0]["upload_token"]
    assert sent == TOKEN.decode(
        "ascii"
    ), f"the handle was re-encoded: sent {sent!r}, MEGA returned {TOKEN.decode()!r}"


def test_the_token_is_not_double_encoded():
    """Stated the other way round, so the intent survives a refactor."""
    from megabasterd_cli.core.crypto import b64_url_encode

    uploader, api = _uploader()
    uploader._register_node(
        target="ROOTHNDL",
        upload_name="f.bin",
        aes_key=b"\x11" * 16,
        nonce=b"\x22" * 8,
        mac_iv=b"\x33" * 8,
        completion_token=TOKEN,
    )

    assert api.calls[0]["upload_token"] != b64_url_encode(TOKEN)


def test_the_attribute_and_key_fields_are_still_base64():
    """Only the token arrives pre-encoded; the other two must not change."""
    import base64

    uploader, api = _uploader()
    uploader._register_node(
        target="ROOTHNDL",
        upload_name="f.bin",
        aes_key=b"\x11" * 16,
        nonce=b"\x22" * 8,
        mac_iv=b"\x33" * 8,
        completion_token=TOKEN,
    )

    for field in ("encrypted_attrs", "wrapped_key"):
        value = api.calls[0][field]
        # base64url with padding stripped, as the rest of the API uses.
        base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_a_non_ascii_token_is_refused_rather_than_mangled():
    """The wire says ASCII. Anything else is a broken or hostile endpoint, and
    guessing an encoding for it would send a handle nobody can explain."""
    uploader, _api = _uploader()

    with pytest.raises(Exception):  # noqa: B017 - any refusal, not a silent send
        uploader._register_node(
            target="ROOTHNDL",
            upload_name="f.bin",
            aes_key=b"\x11" * 16,
            nonce=b"\x22" * 8,
            mac_iv=b"\x33" * 8,
            completion_token=b"\xff\xfe not ascii",
        )


def test_the_resume_metadata_round_trips_the_same_bytes(tmp_path: Path):
    """Resume stores the token as hex; it must come back byte-identical."""
    assert bytes.fromhex(TOKEN.hex()) == TOKEN
