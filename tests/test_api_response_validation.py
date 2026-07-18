"""API responses are validated at the boundary, and proxy health is attributed honestly.

Two defects, one seam:

* `_send` returned `response.json()` unchecked, so a captive portal's HTML page
  or a server sending `{"s": "1234"}` propagated an arbitrary Python object into
  key material, chunk maths and `nodes[0]["h"]` indexing. The user saw
  `Error: 'p'` from the CLI catch-all instead of a typed, actionable MegaError.
* Proxy health was misattributed in BOTH directions: MEGA-side 4xx/5xx counted
  against a blameless proxy (three of them = 60s cooldown), while a captive
  portal answering HTTP 200 with HTML was credited with a success on every
  request - and `SmartProxyPool.pick` weights by success ratio, so the broken
  proxy became progressively PREFERRED.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import requests

from megabasterd_cli.core.api import MegaAPIClient
from megabasterd_cli.core.errors import MegaError


class _Pool:
    """Minimal stand-in for SmartProxyPool that records the verdicts."""

    def __init__(self, url: str = "http://proxy.invalid:8080"):
        self.url = url
        self.successes: list[str] = []
        self.failures: list[str] = []

    def pick(self):
        return SimpleNamespace(url=self.url)

    def report_success(self, url: str) -> None:
        self.successes.append(url)

    def report_failure(self, url: str) -> None:
        self.failures.append(url)


class _Response:
    def __init__(self, payload=None, status_code=200, headers=None, raises=None):
        self._payload = payload
        self.status_code = status_code
        self.headers = headers or {}
        self._raises = raises

    def raise_for_status(self):
        if self._raises is not None:
            raise self._raises

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _Session:
    def __init__(self, response):
        self._response = response
        self.headers: dict = {}
        self.proxies: dict = {}
        self.sent: list = []

    def post(self, url, json=None, timeout=None, headers=None, proxies=None):
        self.sent.append(json)
        if isinstance(self._response, Exception):
            raise self._response
        return self._response

    def close(self):
        return None


def _client(response, pool=None) -> MegaAPIClient:
    client = MegaAPIClient(timeout=1, proxy_pool=pool)
    client._session = _Session(response)
    client.set_session("fake-sid")
    return client


def _http_error(status: int) -> requests.HTTPError:
    resp = requests.Response()
    resp.status_code = status
    return requests.HTTPError(f"HTTP {status}", response=resp)


# ---------------------------------------------------------------------------
# Part 1: unvalidated bodies must not reach field access.
# ---------------------------------------------------------------------------


def test_html_body_raises_a_typed_error_not_a_json_decode_error():
    """A captive portal answers 200 with HTML; the caller must get a MegaError."""
    body = _Response(
        payload=ValueError("Expecting value: line 1 column 1 (char 0)"),
        headers={"Content-Type": "text/html; charset=utf-8"},
    )
    with pytest.raises(MegaError):
        _client(body).request({"a": "ug"})


def test_non_json_content_type_is_refused_before_parsing():
    body = _Response(payload=[{"ok": True}], headers={"Content-Type": "text/html"})
    with pytest.raises(MegaError, match="text/html"):
        _client(body).request({"a": "ug"})


def test_oversized_body_is_refused():
    body = _Response(
        payload=[{"ok": True}],
        headers={"Content-Type": "application/json", "Content-Length": str(1024**3)},
    )
    with pytest.raises(MegaError, match="too large"):
        _client(body).request({"a": "ug"})


def test_top_level_object_is_refused():
    """MEGA answers with an int or a list; anything else is a protocol violation."""
    with pytest.raises(MegaError, match="dict"):
        _client(_Response({"unexpected": "object"})).request({"a": "ug"})


# ---------------------------------------------------------------------------
# Part 2: proxy health attribution, both directions.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [500, 503, 429, 404])
def test_server_side_http_errors_do_not_penalise_the_proxy(status):
    """Three MEGA-side 503s used to cool down a perfectly healthy proxy."""
    pool = _Pool()
    client = _client(_Response(raises=_http_error(status)), pool=pool)
    with pytest.raises(requests.HTTPError):
        client.request({"a": "ug"})
    assert pool.failures == [], f"HTTP {status} came from MEGA, not from the proxy"


def test_proxy_authentication_failure_does_penalise_the_proxy():
    pool = _Pool()
    client = _client(_Response(raises=_http_error(407)), pool=pool)
    with pytest.raises(requests.HTTPError):
        client.request({"a": "ug"})
    assert pool.failures == [pool.url], "407 is the proxy's own refusal"


def test_transport_failures_still_penalise_the_proxy():
    pool = _Pool()
    client = _client(requests.ConnectionError("dead"), pool=pool)
    with pytest.raises(requests.ConnectionError):
        client.request({"a": "ug"})
    assert pool.failures, "a transport failure through a proxy is the proxy's fault"


def test_captive_portal_proxy_is_never_credited_with_success():
    """HTTP 200 + HTML is a broken proxy, and pick() weights by success ratio."""
    pool = _Pool()
    body = _Response(
        payload=ValueError("not json"),
        headers={"Content-Type": "text/html"},
    )
    client = _client(body, pool=pool)
    with pytest.raises(MegaError):
        client.request({"a": "ug"})
    assert pool.successes == [], "an unusable response must not improve the proxy's odds"
    assert pool.failures == [pool.url], "the proxy mangled the response; blame it"


def test_a_usable_response_still_credits_the_proxy():
    pool = _Pool()
    client = _client(
        _Response([{"ok": True}], headers={"Content-Type": "application/json"}), pool=pool
    )
    assert client.request({"a": "ug"}) == {"ok": True}
    assert pool.successes == [pool.url]
    assert pool.failures == []
