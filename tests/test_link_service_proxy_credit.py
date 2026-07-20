"""A proxy is credited only for a response that proved usable, and blamed when it fails.

`SmartProxyPool.pick` weights by success ratio, so crediting a proxy the moment
`requests.post` returns - before `raise_for_status()`, before the body is read -
rewards a captive portal or an error page on every request. Worse, neither ELC
nor MegaCrypter wrapped the POST at all, so a proxy that refused the connection
or timed out was never blamed: a dead proxy became progressively PREFERRED.
`core.api._send` already had the right ordering; the link services now match it.

The second half covers the streamed responses left open on the rejection paths
(`stream=True` without a matching `close()`), which never returned their
connection to the urllib3 pool.
"""

from __future__ import annotations

import contextlib
import json

import pytest
import requests

from megabasterd_cli.core import api as api_mod
from megabasterd_cli.core import link_services as ls
from megabasterd_cli.core.links import ElcPayload, parse_link

PROXY = "http://pool-proxy:3128"
ELC_SERVICE = "https://elc.example.com/api"
MC_LINK = "mc://mc.example.com/token"


class _Selector:
    """ProxySelector double that records what the caller reported, and when."""

    def __init__(self):
        self.selected = 0
        self.successes: list[str] = []
        self.failures: list[str] = []

    def select(self):
        self.selected += 1
        return {"http": PROXY, "https": PROXY}, PROXY

    def report_success(self, picked):
        self.successes.append(picked)

    def report_failure(self, picked):
        self.failures.append(picked)


class _Resp:
    def __init__(self, body=None, status_code: int = 200, headers: dict | None = None, fail=False):
        self._body = {} if body is None else body
        self.status_code = status_code
        self.headers = headers or {}
        self.closed = False
        self._fail = fail

    def iter_content(self, chunk_size=65536):
        yield json.dumps(self._body).encode()

    def raise_for_status(self):
        if self._fail:
            raise requests.HTTPError("500 Server Error", response=self)

    def close(self):
        self.closed = True


def _elc(monkeypatch):
    monkeypatch.setattr(
        ls,
        "decode_elc_payload",
        lambda parsed: ElcPayload(
            encrypted_links=b"x" * 16, service_url=ELC_SERVICE, data_token="tok"
        ),
    )
    return object()


def _post_returns(monkeypatch, response):
    monkeypatch.setattr("requests.post", lambda url, **kw: response)


def _post_raises(monkeypatch, exc):
    def boom(url, **kw):
        raise exc

    monkeypatch.setattr("requests.post", boom)


def _resolve_elc(parsed, selector):
    return ls.resolve_elc_links(parsed, user="u", api_key="k", selector=selector)


# ---------------------------------------------------------------------------
# N2 - credit only a usable response; blame a transport failure
# ---------------------------------------------------------------------------


def test_elc_does_not_credit_a_proxy_for_an_error_status(monkeypatch):
    parsed = _elc(monkeypatch)
    selector = _Selector()
    _post_returns(monkeypatch, _Resp(fail=True))
    with pytest.raises(requests.HTTPError):
        _resolve_elc(parsed, selector)
    assert selector.successes == []


def test_megacrypter_does_not_credit_a_proxy_for_an_error_status(monkeypatch):
    selector = _Selector()
    _post_returns(monkeypatch, _Resp(fail=True))
    with pytest.raises(requests.HTTPError):
        ls.get_megacrypter_info(parse_link(MC_LINK), selector=selector)
    assert selector.successes == []


def test_dlc_does_not_credit_a_proxy_for_an_error_status(monkeypatch):
    selector = _Selector()
    _post_returns(monkeypatch, _Resp(fail=True))
    with pytest.raises(requests.HTTPError):
        ls.decrypt_dlc_container("B" * 100, selector=selector)
    assert selector.successes == []


@pytest.mark.parametrize(
    "exc",
    [requests.ConnectionError("refused"), requests.Timeout("timed out")],
)
def test_elc_blames_the_proxy_when_the_post_fails(monkeypatch, exc):
    parsed = _elc(monkeypatch)
    selector = _Selector()
    _post_raises(monkeypatch, exc)
    with pytest.raises(requests.RequestException):
        _resolve_elc(parsed, selector)
    assert selector.failures == [PROXY]
    assert selector.successes == []


@pytest.mark.parametrize(
    "exc",
    [requests.ConnectionError("refused"), requests.Timeout("timed out")],
)
def test_megacrypter_blames_the_proxy_when_the_post_fails(monkeypatch, exc):
    selector = _Selector()
    _post_raises(monkeypatch, exc)
    with pytest.raises(requests.RequestException):
        ls.get_megacrypter_info(parse_link(MC_LINK), selector=selector)
    assert selector.failures == [PROXY]


@pytest.mark.parametrize(
    "exc",
    [requests.ConnectionError("refused"), requests.Timeout("timed out")],
)
def test_dlc_blames_the_proxy_when_the_post_fails(monkeypatch, exc):
    selector = _Selector()
    _post_raises(monkeypatch, exc)
    with pytest.raises(requests.RequestException):
        ls.decrypt_dlc_container("B" * 100, selector=selector)
    assert selector.failures == [PROXY]


def test_elc_credits_the_proxy_once_the_body_was_read(monkeypatch):
    parsed = _elc(monkeypatch)
    selector = _Selector()
    _post_returns(monkeypatch, _Resp({"d": ""}))
    with pytest.raises(ValueError):  # body read fine; it just carries no key
        _resolve_elc(parsed, selector)
    assert selector.successes == [PROXY]


def test_dlc_credits_the_proxy_once_the_body_was_read(monkeypatch):
    """`_dlc_post` discarded its pick entirely: no credit, and no blame."""
    selector = _Selector()
    _post_returns(monkeypatch, _Resp({}))  # a body, just not a DLC one
    with contextlib.suppress(Exception):
        ls.decrypt_dlc_container("B" * 100, selector=selector)
    assert selector.successes == [PROXY]


def test_a_redirect_hop_selects_a_proxy_of_its_own(monkeypatch):
    parsed = _elc(monkeypatch)
    selector = _Selector()
    seq = [
        _Resp(status_code=307, headers={"Location": "https://mirror.example.com/api"}),
        _Resp({"d": ""}),
    ]
    monkeypatch.setattr("requests.post", lambda url, **kw: seq.pop(0))
    with pytest.raises(ValueError):
        _resolve_elc(parsed, selector)
    assert selector.selected == 2, "a redirect must never downgrade to a direct request"


# ---------------------------------------------------------------------------
# N4 - a streamed response is closed even when it is rejected
# ---------------------------------------------------------------------------


def test_elc_closes_the_response_on_an_error_status(monkeypatch):
    parsed = _elc(monkeypatch)
    response = _Resp(fail=True)
    _post_returns(monkeypatch, response)
    with pytest.raises(requests.HTTPError):
        _resolve_elc(parsed, _Selector())
    assert response.closed


def test_megacrypter_closes_the_response_on_an_error_status(monkeypatch):
    response = _Resp(fail=True)
    _post_returns(monkeypatch, response)
    with pytest.raises(requests.HTTPError):
        ls.get_megacrypter_info(parse_link(MC_LINK), selector=_Selector())
    assert response.closed


def test_link_service_closes_the_response_after_a_successful_read(monkeypatch):
    parsed = _elc(monkeypatch)
    response = _Resp({"d": ""})
    _post_returns(monkeypatch, response)
    with pytest.raises(ValueError):
        _resolve_elc(parsed, _Selector())
    assert response.closed


class _ApiResp(_Resp):
    """MEGA API replies are JSON and must declare it, or `_parse_body` rejects them."""

    def __init__(self, body=None, fail=False):
        super().__init__(body, headers={"Content-Type": "application/json"}, fail=fail)


def test_api_send_closes_the_response_on_an_error_status(monkeypatch):
    client = api_mod.MegaAPIClient()
    response = _ApiResp([0], fail=True)
    monkeypatch.setattr(client._session, "post", lambda url, **kw: response)
    with pytest.raises(requests.HTTPError):
        client._send({"a": "ug"})
    assert response.closed


def test_api_send_closes_the_response_on_an_unusable_body(monkeypatch):
    client = api_mod.MegaAPIClient()
    response = _Resp("<html>captive portal</html>", headers={"Content-Type": "text/html"})
    monkeypatch.setattr(client._session, "post", lambda url, **kw: response)
    with pytest.raises(Exception):  # noqa: B017 - MegaError
        client._send({"a": "ug"})
    assert response.closed


def test_api_send_closes_the_response_on_success(monkeypatch):
    client = api_mod.MegaAPIClient()
    response = _ApiResp([{"ok": 1}])
    monkeypatch.setattr(client._session, "post", lambda url, **kw: response)
    assert client._send({"a": "ug"}) == {"ok": 1}
    assert response.closed
