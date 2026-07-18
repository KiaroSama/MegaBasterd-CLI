"""The chunk downloader must reject a range the server did not honor.

Each chunk body is decrypted with an AES-CTR counter derived from that chunk's
OFFSET and written at that offset. The downloader accepted HTTP 200 for a
partial request and never looked at `Content-Range`, so a CDN or proxy that
ignored `Range` - returning the whole file, or a different window of the same
length - produced silent on-disk corruption. Only a full MAC check would ever
notice, and only when integrity verification is enabled.

The rule now comes from `core/range_validation.py`, shared with streaming.
"""

from __future__ import annotations

import pytest

from megabasterd_cli.core.errors import TransferError
from megabasterd_cli.core.range_validation import (
    RangeNotHonoredError,
    validate_range_response,
)


@pytest.fixture(autouse=True)
def _no_retry_backoff(monkeypatch):
    """Exercise the validation, not tenacity's wall-clock backoff.

    `_download_chunk` is wrapped in an exponential-backoff retry; without this
    these tests spend minutes sleeping between attempts.
    """
    from tenacity import wait_none

    from megabasterd_cli.core import downloader as dl

    for attribute in ("_download_chunk",):
        target = getattr(dl.MegaDownloader, attribute, None)
        retry_state = getattr(target, "retry", None)
        if retry_state is not None:
            monkeypatch.setattr(retry_state, "wait", wait_none(), raising=False)


TOTAL = 4 * 1024 * 1024


class _Resp:
    def __init__(self, status_code, headers, body=b""):
        self.status_code = status_code
        self.headers = headers
        self._body = body

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def close(self):
        return None


def _chunk_request(monkeypatch, response, offset=1024, size=1024):
    """Drive the real `_download_chunk` against one crafted response."""
    from megabasterd_cli.core.chunks import Chunk
    from megabasterd_cli.core.downloader import MegaDownloader
    from megabasterd_cli.core.state import TransferState

    downloader = MegaDownloader(api=None, verify_integrity=False, max_workers=1)
    downloader._cdn_url = "https://cdn.invalid/file"
    monkeypatch.setattr("megabasterd_cli.core.downloader.requests.get", lambda *a, **kw: response)
    state = TransferState(
        transfer_type="download",
        source="https://mega.nz/file/ID#<key>",
        destination="unused",
        total_size=TOTAL,
    )
    chunk = Chunk(index=1, offset=offset, size=size)
    return downloader, chunk, state


# ---------------------------------------------------------------------------
# The shared policy
# ---------------------------------------------------------------------------


def test_a_partial_request_answered_with_200_is_rejected():
    with pytest.raises(RangeNotHonoredError):
        validate_range_response(200, {"Content-Length": str(TOTAL)}, 1024, 2047, TOTAL)


def test_a_wrong_offset_of_the_same_length_is_rejected():
    """The nastiest case: right size, wrong bytes."""
    with pytest.raises(RangeNotHonoredError):
        validate_range_response(
            206,
            {"Content-Range": f"bytes 2048-3071/{TOTAL}", "Content-Length": "1024"},
            1024,
            2047,
            TOTAL,
        )


def test_a_missing_content_range_on_206_is_rejected():
    with pytest.raises(RangeNotHonoredError):
        validate_range_response(206, {"Content-Length": "1024"}, 1024, 2047, TOTAL)


def test_an_unknown_total_is_rejected_when_the_size_is_known():
    with pytest.raises(RangeNotHonoredError):
        validate_range_response(206, {"Content-Range": "bytes 1024-2047/*"}, 1024, 2047, TOTAL)


def test_a_declared_length_mismatch_is_rejected():
    with pytest.raises(RangeNotHonoredError):
        validate_range_response(
            206,
            {"Content-Range": f"bytes 1024-2047/{TOTAL}", "Content-Length": "99"},
            1024,
            2047,
            TOTAL,
        )


def test_the_honored_range_is_accepted():
    validate_range_response(
        206,
        {"Content-Range": f"bytes 1024-2047/{TOTAL}", "Content-Length": "1024"},
        1024,
        2047,
        TOTAL,
    )


def test_a_whole_file_request_may_be_answered_with_200():
    validate_range_response(200, {"Content-Length": str(TOTAL)}, 0, TOTAL - 1, TOTAL)


# ---------------------------------------------------------------------------
# The downloader actually applies it
# ---------------------------------------------------------------------------


def test_downloader_rejects_a_full_body_for_a_chunk_request(monkeypatch):
    """The regression: these bytes used to be decrypted and written."""
    response = _Resp(200, {"Content-Length": str(TOTAL)}, b"\x00" * 4096)
    downloader, chunk, state = _chunk_request(monkeypatch, response)
    with pytest.raises(TransferError, match="range"):
        downloader._download_chunk(chunk, b"\x00" * 16, b"\x00" * 8, "unused", state)


def test_downloader_rejects_a_wrong_offset_same_length_body(monkeypatch):
    response = _Resp(
        206,
        {"Content-Range": f"bytes 2048-3071/{TOTAL}", "Content-Length": "1024"},
        b"\x00" * 1024,
    )
    downloader, chunk, state = _chunk_request(monkeypatch, response)
    with pytest.raises(TransferError, match="range"):
        downloader._download_chunk(chunk, b"\x00" * 16, b"\x00" * 8, "unused", state)


def test_downloader_rejects_a_206_without_content_range(monkeypatch):
    response = _Resp(206, {"Content-Length": "1024"}, b"\x00" * 1024)
    downloader, chunk, state = _chunk_request(monkeypatch, response)
    with pytest.raises(TransferError, match="range"):
        downloader._download_chunk(chunk, b"\x00" * 16, b"\x00" * 8, "unused", state)


def test_the_rejection_is_not_a_retryable_cdn_expiry(monkeypatch):
    """A protocol violation must not be retried against the same server."""
    from megabasterd_cli.core.downloader import CdnUrlExpired

    response = _Resp(200, {"Content-Length": str(TOTAL)}, b"\x00" * 4096)
    downloader, chunk, state = _chunk_request(monkeypatch, response)
    with pytest.raises(TransferError) as caught:
        downloader._download_chunk(chunk, b"\x00" * 16, b"\x00" * 8, "unused", state)
    assert not isinstance(caught.value, CdnUrlExpired)


def test_streaming_and_downloader_share_one_validator():
    """Two copies would drift, which is how the downloader lagged behind."""
    from megabasterd_cli.core import downloader as dl
    from megabasterd_cli.streaming import server as srv

    assert srv.validate_range_response is validate_range_response
    assert dl.validate_range_response is validate_range_response
