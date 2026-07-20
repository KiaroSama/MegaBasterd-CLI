"""Two ways a wrong-but-silent key/offset reaches the user.

Both defects share a shape: the code produces plausible bytes, raises nothing,
and the damage only shows up as corrupt output.

1. `_pump` zeroed the CTR alignment skip after slicing, even when the slice
   consumed nothing. A first upstream block shorter than the skip therefore
   dropped the remaining skip and served plaintext shifted backwards - with
   `sent == length`, so no short-body error fired either.
2. `bytes_to_a32` zero-pads to a word boundary, so a link key that lost one
   base64 character still yielded exactly 8 uint32s and sailed through
   `unpack_file_key`'s length guard as a DIFFERENT key.
"""

from __future__ import annotations

import os

import pytest

from megabasterd_cli.core import download_source as ds
from megabasterd_cli.core.crypto import b64_url_encode, make_ctr_cipher
from megabasterd_cli.core.errors import MegaError
from megabasterd_cli.core.links import parse_link
from megabasterd_cli.streaming import server as srv

# Twelve call sites decode a link key and all of them pass through
# `require_link_key` first, so that is where the length check lives - it raises
# `MegaError`, matching its existing missing-key refusal. `decode_link_key` in
# `download_source` keeps its own check as a parse-boundary backstop and raises
# `ValueError`. Either type means the truncated key was refused, which is what
# these tests are about; the message is the part that has to be specific.
KEY_REFUSED = (ValueError, MegaError)

# ---------------------------------------------------------------------------
# C2: unaligned Range whose first upstream block is shorter than the skip
# ---------------------------------------------------------------------------

KEY = bytes(range(16))
NONCE = bytes(range(8))


class _ChunkedResponse:
    """Upstream that hands back a deliberately tiny first chunk."""

    def __init__(self, body: bytes, first_chunk: int):
        self._body = body
        self._first = first_chunk

    def iter_content(self, chunk_size=65536):
        yield self._body[: self._first]
        yield self._body[self._first :]

    def close(self):
        pass


class _Sink:
    def __init__(self):
        self.data = b""

    def write(self, chunk):
        self.data += chunk


def _pump(body: bytes, first_chunk: int, block_skip: int, length: int, start: int, end: int):
    handler = object.__new__(srv._StreamingRequestHandler)
    sink = _Sink()
    handler.wfile = sink
    cipher = make_ctr_cipher(KEY, NONCE, initial_value=0)
    srv._StreamingRequestHandler._pump(
        handler, _ChunkedResponse(body, first_chunk), cipher, block_skip, length, start, end
    )
    return sink.data


def test_short_first_block_does_not_drop_the_ctr_skip():
    """Range 5-63: the first 2-byte block must not consume the whole skip."""
    plaintext = bytes(range(64))
    ciphertext = make_ctr_cipher(KEY, NONCE, initial_value=0).encrypt(plaintext)

    start, end = 5, 63
    served = _pump(
        ciphertext, first_chunk=2, block_skip=start, length=end - start + 1, start=start, end=end
    )

    assert served == plaintext[start : end + 1]


def test_skip_still_works_when_the_first_block_is_long_enough():
    """The ordinary path stays intact."""
    plaintext = bytes(range(64))
    ciphertext = make_ctr_cipher(KEY, NONCE, initial_value=0).encrypt(plaintext)

    start, end = 5, 63
    served = _pump(
        ciphertext, first_chunk=64, block_skip=start, length=end - start + 1, start=start, end=end
    )

    assert served == plaintext[start : end + 1]


def test_skip_spread_over_several_tiny_blocks():
    """A skip of 15 consumed one byte at a time still lands on the right offset."""
    plaintext = bytes(range(64))
    ciphertext = make_ctr_cipher(KEY, NONCE, initial_value=0).encrypt(plaintext)

    handler = object.__new__(srv._StreamingRequestHandler)
    sink = _Sink()
    handler.wfile = sink

    class _OneByteAtATime:
        def iter_content(self, chunk_size=65536):
            for i in range(len(ciphertext)):
                yield ciphertext[i : i + 1]

        def close(self):
            pass

    start, end = 15, 63
    srv._StreamingRequestHandler._pump(
        handler,
        _OneByteAtATime(),
        make_ctr_cipher(KEY, NONCE, initial_value=0),
        start,
        end - start + 1,
        start,
        end,
    )
    assert sink.data == plaintext[start : end + 1]


# ---------------------------------------------------------------------------
# C3: a link key that lost a base64 character
# ---------------------------------------------------------------------------


class _StubApi:
    def __init__(self, info=None, listing=None):
        self._info = info or {}
        self._listing = listing or {"f": []}

    def get_public_file_info(self, public_id):
        return dict(self._info)

    def get_public_folder_listing(self, folder_id):
        return dict(self._listing)

    def request(self, payload, extra_params=None):
        return dict(self._info)


class _StubDownloader:
    timeout = 5
    _selector = None

    def __init__(self, api):
        self.api = api

    def _get_with_quota_wait(self, fn):
        return fn()


def _file_link(key_b64: str) -> str:
    return f"https://mega.nz/file/AAAAAAAA#{key_b64}"


def test_truncated_file_link_key_is_rejected(tmp_path):
    """42 base64 chars decode to 31 bytes; padding made that look like a valid key."""
    full = b64_url_encode(os.urandom(32))
    dl = _StubDownloader(_StubApi(info={"g": "http://cdn.invalid/x", "s": 1024, "at": ""}))

    # Sanity: the intact key resolves.
    ok = ds.resolve_download_source(dl, _file_link(full), tmp_path, None, None)
    assert len(ok.aes_key) == 16

    with pytest.raises(KEY_REFUSED, match="31 bytes"):
        ds.resolve_download_source(dl, _file_link(full[:-1]), tmp_path, None, None)


def test_truncated_folder_link_key_is_rejected():
    """A folder key is 16 bytes; a 15-byte one silently decrypted node keys wrong.

    Two characters, not one: 21 base64 characters are not a decodable length,
    so that case already errored out. 20 characters decode cleanly to 15 bytes,
    which is exactly what the zero-padding used to hide.
    """
    full = b64_url_encode(os.urandom(16))
    dl = _StubDownloader(_StubApi(listing={"f": []}))

    parsed = parse_link(f"https://mega.nz/folder/AAAAAAAA#{full[:-2]}/file/BBBBBBBB")
    with pytest.raises(KEY_REFUSED, match="15 bytes"):
        ds._resolve_folder_file(dl, parsed)
