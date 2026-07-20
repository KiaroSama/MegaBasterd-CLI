"""A proxy that mangles an HTTP 200 must be blamed exactly once.

Reporting success only after validation fixed half the problem: a proxy
answering 200 with a garbage body is no longer *credited*. But it was not
*debited* either, so it kept its ratio intact and `SmartProxyPool.pick` went
on choosing it. Every protocol violation on a 200 is now one failure report.

Excluded on purpose: 403/404/410/509. Those mean MEGA retired the upload slot,
not that the proxy misbehaved - neither success nor failure.

The doubles come from `test_upload_token_and_retry_policy`, which owns the
token/retry policy assertions this file must not weaken.
"""

from __future__ import annotations

import pytest
import requests

from megabasterd_cli.core.errors import NonRetryableTransferError, RetryableTransferError
from megabasterd_cli.core.upload_transport import (
    MAX_UPLOAD_RESPONSE_BYTES,
    UPLOAD_URL_EXPIRY_STATUS,
    UploadUrlExpiredError,
    upload_chunk,
)

from .test_upload_token_and_retry_policy import (
    TOTAL,
    _chunk,
    _Pool,
    _Resp,
    _run,
    _state,
    _Uploader,
)

FINAL = 2  # chunk index holding the last byte of TOTAL
NON_FINAL = 0


@pytest.fixture
def source(tmp_path):
    """Local copy: importing the fixture shadows the argument in every test."""
    path = tmp_path / "payload.bin"
    path.write_bytes(b"x" * TOTAL)
    return path


def _expect_blame(monkeypatch, source, tmp_path, chunk_index, resp, match):
    pool = _Pool()
    up = _Uploader(pool)
    state = _state(source, tmp_path)

    with pytest.raises(NonRetryableTransferError, match=match):
        _run(monkeypatch, up, source, state, _chunk(chunk_index), resp)

    assert pool.successes == [], "a malformed 200 was credited to the proxy"
    assert pool.failures == ["proxy-1"], f"expected exactly one blame, got {pool.failures}"


# ---------------------------------------------------------------------------
# Malformed HTTP 200 -> exactly one failure, zero successes
# ---------------------------------------------------------------------------


def test_an_oversized_body_blames_the_proxy_once(monkeypatch, source, tmp_path):
    _expect_blame(
        monkeypatch,
        source,
        tmp_path,
        FINAL,
        _Resp(200, b"A" * (MAX_UPLOAD_RESPONSE_BYTES + 1)),
        "more than",
    )


def test_a_token_on_a_non_final_chunk_blames_the_proxy_once(monkeypatch, source, tmp_path):
    _expect_blame(
        monkeypatch, source, tmp_path, NON_FINAL, _Resp(200, b"TOKEN"), "not the final chunk"
    )


def test_a_missing_token_on_the_final_chunk_blames_the_proxy_once(monkeypatch, source, tmp_path):
    _expect_blame(monkeypatch, source, tmp_path, FINAL, _Resp(200, b""), "no completion token")


def test_a_malformed_token_blames_the_proxy_once(monkeypatch, source, tmp_path):
    """A token-shaped body on the wrong chunk is the only malformation the

    transport can detect; the token's own bytes are opaque here. Sent on a
    non-final chunk with binary junk, it is still a protocol violation.
    """
    _expect_blame(
        monkeypatch,
        source,
        tmp_path,
        NON_FINAL,
        _Resp(200, b"\x00\xff\xfe garbage-token \x01"),
        "not the final chunk",
    )


def test_a_body_read_failure_blames_the_proxy_once(monkeypatch, source, tmp_path):
    """The 200 arrived, then the proxy dropped the body mid-stream."""

    class _Broken(_Resp):
        def iter_content(self, chunk_size=65536):
            raise requests.ConnectionError("proxy dropped the body")
            yield  # pragma: no cover - generator marker

    pool = _Pool()
    up = _Uploader(pool)
    state = _state(source, tmp_path)

    with pytest.raises(requests.ConnectionError):
        _run(monkeypatch, up, source, state, _chunk(FINAL), _Broken(200))

    assert pool.successes == []
    # ConnectionError is retryable: one blame per attempt, never two per attempt.
    assert pool.failures == ["proxy-1"] * 5, f"expected one blame per attempt, got {pool.failures}"


# ---------------------------------------------------------------------------
# The good path and the excluded statuses are unchanged
# ---------------------------------------------------------------------------


def test_a_valid_final_response_reports_one_success_and_no_failure(monkeypatch, source, tmp_path):
    pool = _Pool()
    up = _Uploader(pool)
    state = _state(source, tmp_path)

    _run(monkeypatch, up, source, state, _chunk(FINAL), _Resp(200, b"TOKEN"))

    assert pool.successes == ["proxy-1"]
    assert pool.failures == []


def test_a_valid_non_final_response_reports_one_success_and_no_failure(
    monkeypatch, source, tmp_path
):
    pool = _Pool()
    up = _Uploader(pool)
    state = _state(source, tmp_path)

    _run(monkeypatch, up, source, state, _chunk(NON_FINAL), _Resp(200, b""))

    assert pool.successes == ["proxy-1"]
    assert pool.failures == []


@pytest.mark.parametrize("status", sorted(UPLOAD_URL_EXPIRY_STATUS))
def test_slot_expiry_reports_neither_success_nor_failure(monkeypatch, source, tmp_path, status):
    pool = _Pool()
    up = _Uploader(pool)
    state = _state(source, tmp_path)

    with pytest.raises(UploadUrlExpiredError):
        _run(monkeypatch, up, source, state, _chunk(NON_FINAL), _Resp(status))

    assert pool.successes == []
    assert pool.failures == [], f"HTTP {status} wrongly blamed the proxy"


# ---------------------------------------------------------------------------
# No DOUBLE blame when the exception travels back through tenacity
# ---------------------------------------------------------------------------


def _count_blames(monkeypatch, source, tmp_path, post, expected_exc):
    pool = _Pool()
    up = _Uploader(pool)
    state = _state(source, tmp_path)
    monkeypatch.setattr("megabasterd_cli.core.upload_transport.requests.post", post)
    upload_chunk.retry.wait = lambda *a, **kw: 0

    with pytest.raises(expected_exc):
        upload_chunk(
            up,
            "https://up.invalid/s",
            source,
            _chunk(NON_FINAL),
            b"\x00" * 16,
            b"\x00" * 8,
            state,
        )
    assert pool.successes == []
    return pool.failures, up


def test_a_connection_error_blames_once_per_attempt(monkeypatch, source, tmp_path):
    attempts = []

    def _post(*a, **kw):
        attempts.append(1)
        raise requests.ConnectionError("reset")

    failures, _ = _count_blames(monkeypatch, source, tmp_path, _post, requests.ConnectionError)
    assert len(failures) == len(attempts), f"{len(failures)} blames for {len(attempts)} attempts"


def test_a_timeout_blames_once_per_attempt(monkeypatch, source, tmp_path):
    attempts = []

    def _post(*a, **kw):
        attempts.append(1)
        raise requests.Timeout("slow")

    failures, _ = _count_blames(monkeypatch, source, tmp_path, _post, requests.Timeout)
    assert len(failures) == len(attempts), f"{len(failures)} blames for {len(attempts)} attempts"


def test_a_fixed_4xx_blames_exactly_once(monkeypatch, source, tmp_path):
    attempts = []

    def _post(*a, **kw):
        attempts.append(1)
        return _Resp(400)

    failures, _ = _count_blames(monkeypatch, source, tmp_path, _post, NonRetryableTransferError)
    assert len(attempts) == 1
    assert failures == ["proxy-1"]


def test_a_5xx_blames_once_per_attempt(monkeypatch, source, tmp_path):
    attempts = []

    def _post(*a, **kw):
        attempts.append(1)
        return _Resp(503)

    failures, _ = _count_blames(monkeypatch, source, tmp_path, _post, RetryableTransferError)
    assert len(attempts) == 5
    assert len(failures) == 5, f"{len(failures)} blames for 5 attempts"


def test_the_total_size_boundary_still_decides_finality():
    """Guards the FINAL/NON_FINAL constants this file is built on."""
    assert _chunk(FINAL).offset + _chunk(FINAL).size >= TOTAL
    assert _chunk(NON_FINAL).offset + _chunk(NON_FINAL).size < TOTAL
