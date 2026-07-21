"""The completion token comes from the final chunk, or from nowhere.

MEGA answers a chunk POST with a non-empty body for exactly one chunk: the one
holding the file's last byte. That body is the completion token the upload is
finalised against.

The uploader used to accept a token from whichever chunk happened to return
one, with a comment explaining this avoided a race. It did the opposite - any
chunk could nominate itself as the finaliser, so a broken or intercepting
endpoint could hand a token back early and have the upload registered against
it. The offset decides now.

Two policies ride along, both about the same failure of defaults:
  * proxy success was reported BEFORE the body was read and validated, so a
    proxy answering 200 with garbage was credited every time - and the pool
    weights selection by success ratio, so it was progressively preferred;
  * the retry predicates were denylists over `TransferError`, which retries
    anything new by default. Both are allowlists now.
"""

from __future__ import annotations

import threading

import pytest
import requests

from megabasterd_cli.core.chunks import Chunk
from megabasterd_cli.core.errors import (
    NonRetryableTransferError,
    RetryableTransferError,
    TransferCancelled,
    TransferError,
)
from megabasterd_cli.core.state import TransferState
from megabasterd_cli.core.upload_transport import (
    is_final_chunk,
    is_retryable_upload_error,
    upload_chunk,
)
from megabasterd_cli.proxy.selector import ProxyRequiredError, ProxySelector

TOTAL = 3072
CHUNK_SIZE = 1024


class _Resp:
    def __init__(self, status: int, body: bytes = b""):
        self.status_code = status
        self._body = body

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]

    def close(self):
        return None


class _Pool:
    """Records proxy health reports so ordering can be asserted."""

    def __init__(self):
        self.successes: list[str] = []
        self.failures: list[str] = []

    def report_success(self, proxy):
        self.successes.append(proxy)

    def report_failure(self, proxy):
        self.failures.append(proxy)


class _Uploader:
    """The minimum surface `upload_chunk` touches."""

    def __init__(self, pool=None):
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._bytes_done = 0
        self._chunks_done = 0
        self._completion_token = b""
        self.timeout = 5
        self.user_agent = "test"
        self.proxy_pool = pool
        # Mirror the real uploader: reporting goes through a persistent selector
        # over the same pool, not a raw `proxy_pool.report_*` call.
        self._selector = ProxySelector(pool=pool)
        self.limiter = type("L", (), {"consume": lambda self, n: None})()
        self._speed_meter = type("M", (), {"update": lambda self, n: None})()

    def _proxies_for_request(self):
        return None, ("proxy-1" if self.proxy_pool else None)


@pytest.fixture
def source(tmp_path):
    path = tmp_path / "payload.bin"
    path.write_bytes(b"x" * TOTAL)
    return path


def _state(source, tmp_path) -> TransferState:
    return TransferState(
        transfer_type="upload",
        source=str(source),
        destination=str(tmp_path / "payload.bin.upload"),
        total_size=TOTAL,
    )


def _chunk(index: int) -> Chunk:
    return Chunk(index=index, offset=index * CHUNK_SIZE, size=CHUNK_SIZE)


def _run(monkeypatch, up, source, state, chunk, response):
    monkeypatch.setattr(
        "megabasterd_cli.core.upload_transport.requests.post",
        lambda *a, **kw: response,
    )
    upload_chunk.retry.wait = lambda *a, **kw: 0  # no backoff in tests
    return upload_chunk(
        up, "https://up.invalid/slot", source, chunk, b"\x00" * 16, b"\x00" * 8, state
    )


# ---------------------------------------------------------------------------
# Which chunk is final is decided by the offset
# ---------------------------------------------------------------------------


def test_only_the_offset_final_chunk_is_final():
    assert not is_final_chunk(_chunk(0), TOTAL)
    assert not is_final_chunk(_chunk(1), TOTAL)
    assert is_final_chunk(_chunk(2), TOTAL)


def test_upload_chunk_still_accepts_the_1x_total_chunks_argument(monkeypatch, source, tmp_path):
    """`total_chunks` was a public parameter; a 1.x caller still passing the
    eighth argument must not get a TypeError. It is accepted and ignored."""
    up = _Uploader()
    state = _state(source, tmp_path)
    # The old eight-argument form, with total_chunks passed positionally; a
    # final chunk (index 2) whose response carries the completion token.
    _run(monkeypatch, up, source, state, _chunk(2), _Resp(200, b"TOKEN"))
    upload_chunk(up, "https://up.invalid/s", source, _chunk(2), b"\x00" * 16, b"\x00" * 8, state, 3)


# ---------------------------------------------------------------------------
# Item 3 - the token
# ---------------------------------------------------------------------------


def test_a_token_from_a_non_final_chunk_is_rejected(monkeypatch, source, tmp_path):
    """The regression: this body used to be accepted and finalised against."""
    up = _Uploader()
    state = _state(source, tmp_path)

    with pytest.raises(NonRetryableTransferError, match="not the final chunk"):
        _run(monkeypatch, up, source, state, _chunk(0), _Resp(200, b"TOKEN"))

    assert up._completion_token == b"", "a non-final chunk set the completion token"
    assert "completion_token" not in state.metadata


def test_an_empty_body_from_the_final_chunk_is_rejected(monkeypatch, source, tmp_path):
    up = _Uploader()
    state = _state(source, tmp_path)

    with pytest.raises(NonRetryableTransferError, match="no completion token"):
        _run(monkeypatch, up, source, state, _chunk(2), _Resp(200, b""))


def test_an_oversized_body_is_rejected(monkeypatch, source, tmp_path):
    from megabasterd_cli.core.upload_transport import MAX_UPLOAD_RESPONSE_BYTES

    up = _Uploader()
    state = _state(source, tmp_path)
    huge = b"A" * (MAX_UPLOAD_RESPONSE_BYTES + 1)

    with pytest.raises(NonRetryableTransferError, match="more than"):
        _run(monkeypatch, up, source, state, _chunk(2), _Resp(200, huge))


def test_the_final_chunk_stores_its_token(monkeypatch, source, tmp_path):
    up = _Uploader()
    state = _state(source, tmp_path)

    _run(monkeypatch, up, source, state, _chunk(2), _Resp(200, b"REALTOKEN"))

    assert up._completion_token == b"REALTOKEN"
    assert state.metadata["completion_token"] == b"REALTOKEN".hex()


def test_a_late_worker_cannot_replace_a_recorded_token(monkeypatch, source, tmp_path):
    """Out-of-order completion must not overwrite the token already held."""
    up = _Uploader()
    state = _state(source, tmp_path)

    _run(monkeypatch, up, source, state, _chunk(2), _Resp(200, b"FIRST"))
    _run(monkeypatch, up, source, state, _chunk(2), _Resp(200, b"SECOND"))

    assert up._completion_token == b"FIRST", "a stale worker replaced the token"
    assert state.metadata["completion_token"] == b"FIRST".hex()


def test_an_empty_body_from_a_non_final_chunk_is_normal(monkeypatch, source, tmp_path):
    up = _Uploader()
    state = _state(source, tmp_path)

    _run(monkeypatch, up, source, state, _chunk(0), _Resp(200, b""))

    assert up._completion_token == b""
    assert state.is_chunk_done(0)


# ---------------------------------------------------------------------------
# Item 4 - proxy health is reported after the response is proven good
# ---------------------------------------------------------------------------


def test_a_200_with_an_oversized_body_is_not_a_proxy_success(monkeypatch, source, tmp_path):
    from megabasterd_cli.core.upload_transport import MAX_UPLOAD_RESPONSE_BYTES

    pool = _Pool()
    up = _Uploader(pool)
    state = _state(source, tmp_path)

    with pytest.raises(NonRetryableTransferError):
        _run(
            monkeypatch,
            up,
            source,
            state,
            _chunk(2),
            _Resp(200, b"A" * (MAX_UPLOAD_RESPONSE_BYTES + 1)),
        )

    assert pool.successes == [], "a garbage body was credited to the proxy"


def test_a_token_on_a_non_final_chunk_is_not_a_proxy_success(monkeypatch, source, tmp_path):
    pool = _Pool()
    up = _Uploader(pool)
    state = _state(source, tmp_path)

    with pytest.raises(NonRetryableTransferError):
        _run(monkeypatch, up, source, state, _chunk(0), _Resp(200, b"TOKEN"))

    assert pool.successes == [], "a protocol violation was credited to the proxy"


def test_a_valid_final_response_reports_exactly_one_success(monkeypatch, source, tmp_path):
    pool = _Pool()
    up = _Uploader(pool)
    state = _state(source, tmp_path)

    _run(monkeypatch, up, source, state, _chunk(2), _Resp(200, b"TOKEN"))

    assert pool.successes == ["proxy-1"]
    assert pool.failures == []


def test_a_transport_failure_reports_failure_once(monkeypatch, source, tmp_path):
    pool = _Pool()
    up = _Uploader(pool)
    state = _state(source, tmp_path)

    with pytest.raises(NonRetryableTransferError):
        _run(monkeypatch, up, source, state, _chunk(0), _Resp(400))

    assert pool.failures == ["proxy-1"]
    assert pool.successes == []


def test_an_upload_slot_expiry_does_not_blame_the_proxy(monkeypatch, source, tmp_path):
    """403/404/410/509 mean MEGA retired the slot, not that the proxy misbehaved."""
    from megabasterd_cli.core.upload_transport import (
        UPLOAD_URL_EXPIRY_STATUS,
        UploadUrlExpiredError,
    )

    for status in sorted(UPLOAD_URL_EXPIRY_STATUS):
        pool = _Pool()
        up = _Uploader(pool)
        state = _state(source, tmp_path)

        with pytest.raises(UploadUrlExpiredError):
            _run(monkeypatch, up, source, state, _chunk(0), _Resp(status))

        assert pool.failures == [], f"HTTP {status} wrongly blamed the proxy"
        assert pool.successes == []


# ---------------------------------------------------------------------------
# Item 5 - the retry allowlist
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(NonRetryableTransferError(message="short read"), id="short-read"),
        pytest.param(NonRetryableTransferError(message="oversized"), id="oversized-body"),
        pytest.param(NonRetryableTransferError(message="HTTP 404"), id="deterministic-4xx"),
        pytest.param(ProxyRequiredError(message="no proxy"), id="proxy-policy"),
        pytest.param(TransferCancelled(message="cancelled"), id="cancellation"),
        pytest.param(TransferError(message="unclassified"), id="unclassified-base"),
    ],
)
def test_deterministic_upload_failures_are_not_retried(exc):
    assert is_retryable_upload_error(exc) is False


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(requests.ConnectionError("reset"), id="connection-reset"),
        pytest.param(requests.Timeout("slow"), id="timeout"),
        pytest.param(RetryableTransferError(message="HTTP 503"), id="server-5xx"),
    ],
)
def test_transient_upload_failures_are_retried(exc):
    assert is_retryable_upload_error(exc) is True


def test_a_deterministic_upload_error_makes_exactly_one_attempt(monkeypatch, source, tmp_path):
    """End to end through the real tenacity decorator, counting attempts."""
    up = _Uploader()
    state = _state(source, tmp_path)
    attempts = []

    def _post(*a, **kw):
        # 400, not 404: 404 is in UPLOAD_URL_EXPIRY_STATUS and is deliberately
        # retryable, because the orchestrator refreshes the slot.
        attempts.append(1)
        return _Resp(400)

    monkeypatch.setattr("megabasterd_cli.core.upload_transport.requests.post", _post)
    upload_chunk.retry.wait = lambda *a, **kw: 0

    with pytest.raises(NonRetryableTransferError):
        upload_chunk(
            up, "https://up.invalid/s", source, _chunk(0), b"\x00" * 16, b"\x00" * 8, state
        )

    assert len(attempts) == 1, f"a deterministic 400 was retried {len(attempts)} times"


def test_a_server_error_is_retried_to_the_attempt_limit(monkeypatch, source, tmp_path):
    up = _Uploader()
    state = _state(source, tmp_path)
    attempts = []

    def _post(*a, **kw):
        attempts.append(1)
        return _Resp(503)

    monkeypatch.setattr("megabasterd_cli.core.upload_transport.requests.post", _post)
    upload_chunk.retry.wait = lambda *a, **kw: 0

    with pytest.raises(RetryableTransferError):
        upload_chunk(
            up, "https://up.invalid/s", source, _chunk(0), b"\x00" * 16, b"\x00" * 8, state
        )

    assert len(attempts) == 5, f"a 5xx made {len(attempts)} attempts, expected 5"
