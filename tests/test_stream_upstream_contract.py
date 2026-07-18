"""Streaming upstream contract: forced proxying and strict Range validation.

Two invariants are enforced here, both at the single point where the streaming
server opens an upstream CDN connection:

1. force_smart_proxy: no socket may be opened without a selected proxy. The
   fake transport below FAILS THE TEST the moment an unproxied request is
   attempted - it is not enough to return an error afterwards.
2. Range honesty: streamed plaintext must correspond exactly to the requested
   byte range. A nonzero range answered with HTTP 200 (full body from byte 0)
   would be decrypted with a nonzero AES-CTR counter and served as garbage.
"""

from __future__ import annotations

import pytest
import requests

from megabasterd_cli.proxy.selector import ProxyRequiredError, ProxySelector
from megabasterd_cli.proxy.smart_proxy import SmartProxyPool
from megabasterd_cli.streaming import server as srv


class _FakeResponse:
    def __init__(self, status_code=206, headers=None, body=b"", url="http://cdn.invalid/x"):
        self.status_code = status_code
        self.headers = headers if headers is not None else {}
        self._body = body
        self.url = url
        self.closed = False

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]

    def close(self):
        self.closed = True


class _Source:
    """Minimal stand-in for _StreamSource."""

    def __init__(self, size=4096):
        self.size = size
        self.refreshed = 0

    def current_cdn_url(self):
        return "http://cdn.invalid/file"

    def refresh_cdn_url(self):
        self.refreshed += 1
        return self.current_cdn_url()


class _ServerStub:
    def __init__(self, selector):
        self.selector = selector
        self.source = None


def _handler(selector):
    """A request handler with no socket machinery, only what we exercise."""
    handler = object.__new__(srv._StreamingRequestHandler)
    handler.server = _ServerStub(selector)
    handler.errors = []
    handler.send_error = lambda code, msg=None: handler.errors.append((code, msg))
    return handler


@pytest.fixture()
def no_direct(monkeypatch):
    """Install a transport that fails the test if a request goes out unproxied."""
    calls = []

    def guard(url, **kwargs):
        proxies = kwargs.get("proxies")
        if not proxies:
            raise AssertionError(f"DIRECT (unproxied) request attempted to {url}")
        calls.append((url, proxies))
        return _FakeResponse(
            status_code=206,
            headers={"Content-Range": "bytes 0-4095/4096", "Content-Length": "4096"},
            body=b"\x00" * 4096,
        )

    monkeypatch.setattr(srv.requests, "get", guard)
    return calls


# ---------------------------------------------------------------------------
# 1. force_smart_proxy on the streaming CDN path
# ---------------------------------------------------------------------------


def test_streaming_force_mode_uses_the_pool_proxy(no_direct):
    pool = SmartProxyPool(["http://pool-proxy:3128"])
    selector = ProxySelector(pool=pool, static=None, force=True)
    handler = _handler(selector)
    resp = handler._open_upstream(_Source(), 0, 4095)
    assert resp is not None, handler.errors
    assert no_direct == [
        (
            "http://cdn.invalid/file",
            {"http": "http://pool-proxy:3128", "https": "http://pool-proxy:3128"},
        )
    ]


def test_streaming_force_mode_with_empty_pool_makes_zero_http_calls(monkeypatch):
    attempted = []

    def guard(url, **kwargs):
        attempted.append(url)
        raise AssertionError(f"a request was attempted at all: {url}")

    monkeypatch.setattr(srv.requests, "get", guard)
    selector = ProxySelector(pool=SmartProxyPool(), static=None, force=True)
    handler = _handler(selector)
    resp = handler._open_upstream(_Source(), 0, 4095)
    assert resp is None
    assert attempted == [], "force mode must refuse BEFORE opening a socket"
    assert handler.errors and handler.errors[0][0] == 502


def test_streaming_force_mode_does_not_fall_back_to_direct_after_proxy_failure(monkeypatch):
    """The pool's only proxy fails; force mode must NOT retry without one."""
    seen = []

    def flaky(url, **kwargs):
        seen.append(kwargs.get("proxies"))
        raise requests.ConnectionError("proxy down")

    monkeypatch.setattr(srv.requests, "get", flaky)
    pool = SmartProxyPool(["http://pool-proxy:3128"])
    selector = ProxySelector(pool=pool, static=None, force=True)
    handler = _handler(selector)
    resp = handler._open_upstream(_Source(), 0, 4095)
    assert resp is None
    assert all(p for p in seen), f"a direct retry happened after proxy failure: {seen}"


def test_streaming_static_proxy_still_works(no_direct):
    static = {"http": "http://manual:8080", "https": "http://manual:8080"}
    selector = ProxySelector(pool=None, static=static, force=True)
    handler = _handler(selector)
    assert handler._open_upstream(_Source(), 0, 4095) is not None
    assert no_direct[0][1] == static


def test_streaming_without_force_may_go_direct(monkeypatch):
    seen = []

    def transport(url, **kwargs):
        seen.append(kwargs.get("proxies"))
        return _FakeResponse(
            status_code=206,
            headers={"Content-Range": "bytes 0-4095/4096", "Content-Length": "4096"},
            body=b"\x00" * 4096,
        )

    monkeypatch.setattr(srv.requests, "get", transport)
    handler = _handler(ProxySelector(pool=None, static=None, force=False))
    assert handler._open_upstream(_Source(), 0, 4095) is not None
    assert seen == [None], "non-force mode keeps its documented direct behavior"


def test_selector_refuses_before_any_socket():
    with pytest.raises(ProxyRequiredError):
        ProxySelector(pool=SmartProxyPool(), force=True).select()


# ---------------------------------------------------------------------------
# 2. Strict Range validation
# ---------------------------------------------------------------------------


def _open_with(monkeypatch, response, start, end, size=4096):
    monkeypatch.setattr(srv.requests, "get", lambda url, **kw: response)
    handler = _handler(ProxySelector())
    return handler, handler._open_upstream(_Source(size), start, end)


def test_nonzero_range_answered_with_200_is_rejected(monkeypatch):
    """The core defect: a full body from byte 0 decrypted at a nonzero counter."""
    full = _FakeResponse(status_code=200, headers={"Content-Length": "4096"}, body=b"\x00" * 4096)
    handler, resp = _open_with(monkeypatch, full, 1024, 2047)
    assert resp is None, "HTTP 200 for a nonzero range must never be streamed"
    assert handler.errors and handler.errors[0][0] == 502
    assert full.closed


def test_206_without_content_range_is_rejected(monkeypatch):
    bad = _FakeResponse(status_code=206, headers={}, body=b"\x00" * 1024)
    handler, resp = _open_with(monkeypatch, bad, 1024, 2047)
    assert resp is None and handler.errors[0][0] == 502


@pytest.mark.parametrize(
    "content_range",
    [
        "bytes 0-1023/4096",  # wrong start
        "bytes 1024-4095/4096",  # wrong end
        "bytes 1024-2047/9999",  # wrong total
        "bytes */4096",  # unsatisfiable
        "chunks 1024-2047/4096",  # wrong unit
        "garbage",
    ],
)
def test_mismatched_content_range_is_rejected(monkeypatch, content_range):
    bad = _FakeResponse(
        status_code=206,
        headers={"Content-Range": content_range, "Content-Length": "1024"},
        body=b"\x00" * 1024,
    )
    handler, resp = _open_with(monkeypatch, bad, 1024, 2047)
    assert resp is None, f"{content_range!r} must be rejected"
    assert handler.errors[0][0] == 502


def test_declared_length_mismatch_is_rejected(monkeypatch):
    bad = _FakeResponse(
        status_code=206,
        headers={"Content-Range": "bytes 1024-2047/4096", "Content-Length": "99"},
        body=b"\x00" * 99,
    )
    handler, resp = _open_with(monkeypatch, bad, 1024, 2047)
    assert resp is None and handler.errors[0][0] == 502


def test_valid_partial_range_is_accepted(monkeypatch):
    good = _FakeResponse(
        status_code=206,
        headers={"Content-Range": "bytes 1024-2047/4096", "Content-Length": "1024"},
        body=b"\x00" * 1024,
    )
    handler, resp = _open_with(monkeypatch, good, 1024, 2047)
    assert resp is good, handler.errors


def test_unaligned_range_start_is_accepted_when_honored(monkeypatch):
    """The handler aligns to a 16-byte block; the aligned range must validate."""
    good = _FakeResponse(
        status_code=206,
        headers={"Content-Range": "bytes 1008-2047/4096", "Content-Length": "1040"},
        body=b"\x00" * 1040,
    )
    handler, resp = _open_with(monkeypatch, good, 1008, 2047)
    assert resp is good, handler.errors


def test_full_file_request_may_be_answered_with_200(monkeypatch):
    """Counter starts at zero, so a 200 full body is genuinely correct here."""
    full = _FakeResponse(status_code=200, headers={"Content-Length": "4096"}, body=b"\x00" * 4096)
    handler, resp = _open_with(monkeypatch, full, 0, 4095)
    assert resp is full, handler.errors


def test_full_file_request_accepts_a_matching_206(monkeypatch):
    good = _FakeResponse(
        status_code=206,
        headers={"Content-Range": "bytes 0-4095/4096", "Content-Length": "4096"},
        body=b"\x00" * 4096,
    )
    handler, resp = _open_with(monkeypatch, good, 0, 4095)
    assert resp is good, handler.errors


def test_expired_url_still_refreshes_then_validates(monkeypatch):
    """Retry-after-expiry keeps working, and the retried response is validated."""
    responses = [
        _FakeResponse(status_code=403, headers={}, body=b""),
        _FakeResponse(
            status_code=206,
            headers={"Content-Range": "bytes 1024-2047/4096", "Content-Length": "1024"},
            body=b"\x00" * 1024,
        ),
    ]
    monkeypatch.setattr(srv.requests, "get", lambda url, **kw: responses.pop(0))
    source = _Source()
    handler = _handler(ProxySelector())
    resp = handler._open_upstream(source, 1024, 2047)
    assert source.refreshed == 1
    assert resp is not None, handler.errors
