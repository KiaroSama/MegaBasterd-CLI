"""Strictness regression tests for `b64_url_decode`.

The decoder used to run with `base64`'s default `validate=False`, which
silently *discards* any character outside the base64 alphabet before checking
padding. A tampered/truncated link key carrying junk (e.g. a valid 43-char key
plus four `!`) therefore decoded to the same 32 bytes and slipped past the
length-only guard in `require_link_key`. These tests pin the fix: junk now
raises, while every legitimate input still decodes byte-identically.
"""

import base64
import binascii
import os

import pytest

from megabasterd_cli.core.crypto import b64_url_decode, b64_url_encode


def _ref(data: str) -> bytes:
    """Independent reference decode of MEGA URL-safe base64 (no strictness)."""
    data = data.replace("-", "+").replace("_", "/").replace(",", "")
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.b64decode(data + padding)


# A genuine 43-char key that decodes to 32 bytes, and a genuine 22-char folder
# key that decodes to 16 bytes.
GOOD_FILE_KEY = b64_url_encode(bytes(range(32)))  # 43 chars
GOOD_FOLDER_KEY = b64_url_encode(bytes(range(16)))  # 22 chars


def test_trailing_junk_now_raises():
    """The reported repro: valid key + `!!!!` must be rejected, not stripped."""
    assert len(GOOD_FILE_KEY) == 43
    with pytest.raises((ValueError, binascii.Error)):
        b64_url_decode(GOOD_FILE_KEY + "!!!!")


def test_midstring_junk_now_raises():
    with pytest.raises((ValueError, binascii.Error)):
        b64_url_decode(GOOD_FILE_KEY[:20] + "!" + GOOD_FILE_KEY[20:])


def test_valid_file_key_byte_identical():
    assert b64_url_decode(GOOD_FILE_KEY) == bytes(range(32))
    assert b64_url_decode(GOOD_FILE_KEY) == _ref(GOOD_FILE_KEY)


def test_valid_folder_key_byte_identical():
    assert b64_url_decode(GOOD_FOLDER_KEY) == bytes(range(16))
    assert b64_url_decode(GOOD_FOLDER_KEY) == _ref(GOOD_FOLDER_KEY)


def test_roundtrip_still_byte_identical():
    for n in (1, 15, 16, 31, 32, 33, 64):
        raw = os.urandom(n)
        assert b64_url_decode(b64_url_encode(raw)) == raw


def test_empty_string_still_decodes():
    assert b64_url_decode("") == b""


def test_comma_separator_still_stripped():
    """MEGA uses `,` as a separator artifact; it must stay stripped, not rejected."""
    encoded = GOOD_FILE_KEY
    assert b64_url_decode(encoded[:10] + "," + encoded[10:]) == bytes(range(32))


def test_url_safe_alphabet_accepted():
    """`-` and `_` translate to `+`/`/` and must not be treated as junk."""
    raw = bytes([0xFB, 0xEF, 0xBE, 0xFF, 0x3F])  # forces `-`/`_` in the encoding
    enc = b64_url_encode(raw)
    assert ("-" in enc) or ("_" in enc)
    assert b64_url_decode(enc) == raw
