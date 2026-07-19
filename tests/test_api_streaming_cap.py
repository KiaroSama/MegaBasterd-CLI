"""The API response cap bounds the DOWNLOAD, not just the parse.

Without `stream=True`, `requests` buffers the whole body - and transparently
inflates `Content-Encoding: gzip` - before any size check runs, so the cap was
decoration: a decompression bomb was fully materialised in memory and only then
refused. The body is now read incrementally and abandoned mid-stream.
"""

from __future__ import annotations

import json

import pytest

from megabasterd_cli.core import api as api_module
from megabasterd_cli.core.api import MegaAPIClient
from megabasterd_cli.core.errors import MegaError

CAP = 4096
CHUNK = 1024


class _StreamedResponse:
    """Counts the bytes actually pulled out of the stream."""

    status_code = 200
    encoding = "utf-8"

    def __init__(self, chunks: list[bytes], headers: dict | None = None):
        self._chunks = chunks
        self.headers = headers or {"Content-Type": "application/json"}
        self.pulled = 0
        self.closed = False

    def iter_content(self, chunk_size=None):
        for chunk in self._chunks:
            self.pulled += len(chunk)
            yield chunk

    def raise_for_status(self):
        return None

    def close(self):
        self.closed = True


class _Session:
    def __init__(self, response):
        self._response = response
        self.headers: dict = {}
        self.proxies: dict = {}
        self.stream_flags: list = []

    def post(self, url, json=None, timeout=None, headers=None, proxies=None, stream=False):
        self.stream_flags.append(stream)
        return self._response

    def close(self):
        return None


def _client(response) -> MegaAPIClient:
    client = MegaAPIClient(timeout=1)
    client._session = _Session(response)
    client.set_session("fake-sid")
    return client


@pytest.fixture(autouse=True)
def _small_cap(monkeypatch):
    monkeypatch.setattr(api_module, "MAX_RESPONSE_BYTES", CAP)


def test_the_request_is_streamed():
    body = _StreamedResponse([json.dumps([{"ok": True}]).encode()])
    client = _client(body)
    assert client.request({"a": "ug"}) == {"ok": True}
    assert client._session.stream_flags == [True], "an unbounded body must never be buffered first"


def test_an_oversized_body_is_abandoned_mid_read():
    """1 MiB on the wire, 4 KiB cap: only the cap may ever land in memory."""
    body = _StreamedResponse([b"x" * CHUNK] * 1024)
    with pytest.raises(MegaError, match="too large"):
        _client(body).request({"a": "ug"})
    assert body.pulled <= CAP + CHUNK, (
        f"{body.pulled} bytes were pulled for a {CAP}-byte cap; "
        "the whole body was materialised before the check"
    )
    assert body.closed, "the abandoned response must be closed, not left to drain"


def test_a_body_within_the_cap_still_parses():
    payload = [{"pad": "y" * 512}]
    raw = json.dumps(payload).encode()
    body = _StreamedResponse([raw[i : i + CHUNK] for i in range(0, len(raw), CHUNK)])
    assert _client(body).request({"a": "ug"}) == payload[0]
    assert body.pulled == len(raw)


def test_a_streamed_non_json_body_is_still_a_typed_error():
    body = _StreamedResponse([b"<html>captive portal</html>"], headers={})
    with pytest.raises(MegaError, match="not valid JSON"):
        _client(body).request({"a": "ug"})
