"""force_smart_proxy on the link-resolution paths.

MegaCrypter, DLC, and ELC resolution used to take a plain `proxies` dict that
callers frequently left as None, so force mode was silently unenforced there
(`resolve_megacrypter_link` passed nothing at all). They now select through the
shared ProxySelector, like every other outbound request.

Each transport below FAILS THE TEST the moment an unproxied request is made -
proving the dangerous operation was never attempted, not merely that an error
came back afterwards.
"""

from __future__ import annotations

import pytest

from megabasterd_cli.core import link_services as links
from megabasterd_cli.core.links import parse_link
from megabasterd_cli.proxy.selector import ProxyRequiredError, ProxySelector
from megabasterd_cli.proxy.smart_proxy import SmartProxyPool

POOL_URL = "http://pool-proxy:3128"
MC_URL = "mc://example.invalid/sometoken"
ELC_LINK = None  # built lazily in the ELC test


class _Resp:
    status_code = 200
    headers: dict = {}
    text = "{}"

    def __init__(self, payload=None):
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None

    def close(self):
        return None


@pytest.fixture()
def forbid_direct(monkeypatch):
    """Any request without proxies fails the test immediately."""
    seen = []

    def guard(url, *args, **kwargs):
        proxies = kwargs.get("proxies")
        if not proxies:
            raise AssertionError(f"DIRECT (unproxied) request attempted to {url}")
        seen.append((url, proxies))
        return _Resp({"link": "https://mega.nz/file/ABCDEFGH#key"})

    import requests

    monkeypatch.setattr(requests, "post", guard)
    monkeypatch.setattr(requests, "get", guard)
    return seen


@pytest.fixture()
def forbid_any_request(monkeypatch):
    """No request at all may be attempted."""
    attempted = []

    def guard(url, *args, **kwargs):
        attempted.append(url)
        raise AssertionError(f"a request was attempted at all: {url}")

    import requests

    monkeypatch.setattr(requests, "post", guard)
    monkeypatch.setattr(requests, "get", guard)
    return attempted


def _pool_selector() -> ProxySelector:
    return ProxySelector(pool=SmartProxyPool([POOL_URL]), force=True)


def _empty_forced_selector() -> ProxySelector:
    return ProxySelector(pool=SmartProxyPool(), force=True)


# ---------------------------------------------------------------------------
# MegaCrypter
# ---------------------------------------------------------------------------


def test_megacrypter_resolution_uses_the_selected_proxy(forbid_direct):
    parsed = parse_link(MC_URL)
    links.resolve_megacrypter_link(parsed, selector=_pool_selector())
    assert forbid_direct, "the request must have gone out through the pool proxy"
    assert all(p == {"http": POOL_URL, "https": POOL_URL} for _u, p in forbid_direct)


def test_megacrypter_info_refuses_before_any_request(forbid_any_request):
    parsed = parse_link(MC_URL)
    with pytest.raises(ProxyRequiredError):
        links.get_megacrypter_info(parsed, selector=_empty_forced_selector())
    assert attempted_nothing(forbid_any_request)


def test_megacrypter_download_url_refuses_before_any_request(forbid_any_request):
    parsed = parse_link(MC_URL)
    with pytest.raises(ProxyRequiredError):
        links.get_megacrypter_download_url(parsed, selector=_empty_forced_selector())
    assert attempted_nothing(forbid_any_request)


def test_megacrypter_link_resolution_refuses_before_any_request(forbid_any_request):
    """`resolve_megacrypter_link` previously passed NO proxy information."""
    parsed = parse_link(MC_URL)
    with pytest.raises(ProxyRequiredError):
        links.resolve_megacrypter_link(parsed, selector=_empty_forced_selector())
    assert attempted_nothing(forbid_any_request)


# ---------------------------------------------------------------------------
# DLC
# ---------------------------------------------------------------------------


def test_dlc_refuses_before_any_request(forbid_any_request):
    payload = "A" * 200  # long enough to reach the network stage
    with pytest.raises(ProxyRequiredError):
        links.decrypt_dlc_container(payload, selector=_empty_forced_selector())
    assert attempted_nothing(forbid_any_request)


def test_dlc_uses_the_selected_proxy(forbid_direct):
    payload = "A" * 200
    with pytest.raises(Exception):  # noqa: B017 - the DLC body is not valid here
        links.decrypt_dlc_container(payload, selector=_pool_selector())
    assert forbid_direct, "the DLC POST must have used the pool proxy"


# ---------------------------------------------------------------------------
# ELC
# ---------------------------------------------------------------------------


def _elc_parsed(monkeypatch):
    """Bypass payload decoding; only the network policy is under test."""
    from megabasterd_cli.core.links import ElcPayload

    monkeypatch.setattr(
        links,
        "decode_elc_payload",
        lambda parsed: ElcPayload(
            encrypted_links=b"x" * 16, service_url="https://elc.invalid/api", data_token="tok"
        ),
    )
    return object()


def test_elc_refuses_before_any_request(monkeypatch, forbid_any_request):
    parsed = _elc_parsed(monkeypatch)
    with pytest.raises(ProxyRequiredError):
        links.resolve_elc_links(parsed, user="u", api_key="k", selector=_empty_forced_selector())
    assert attempted_nothing(forbid_any_request)


def test_elc_uses_the_selected_proxy(monkeypatch, forbid_direct):
    parsed = _elc_parsed(monkeypatch)
    with pytest.raises(Exception):  # noqa: B017 - response shape is irrelevant
        links.resolve_elc_links(parsed, user="u", api_key="k", selector=_pool_selector())
    assert forbid_direct
    assert all(p == {"http": POOL_URL, "https": POOL_URL} for _u, p in forbid_direct)


# ---------------------------------------------------------------------------
# Non-force behavior stays backward compatible
# ---------------------------------------------------------------------------


def test_without_force_link_resolution_may_go_direct(monkeypatch):
    seen = []

    def transport(url, *args, **kwargs):
        seen.append(kwargs.get("proxies"))
        return _Resp({"link": "https://mega.nz/file/ABCDEFGH#key"})

    import requests

    monkeypatch.setattr(requests, "post", transport)
    parsed = _elc_parsed(monkeypatch)
    with pytest.raises(Exception):  # noqa: B017
        # The policy must be stated EXPLICITLY: omitting it is now an error, so
        # a forgetful caller can no longer inherit direct access by accident.
        links.resolve_elc_links(parsed, user="u", api_key="k", selector=ProxySelector(force=False))
    assert seen == [None], "an explicit non-force policy keeps direct behavior"


def test_static_proxy_is_used_when_no_pool_exists(monkeypatch):
    seen = []

    def transport(url, *args, **kwargs):
        seen.append(kwargs.get("proxies"))
        return _Resp({"link": "https://mega.nz/file/ABCDEFGH#key"})

    import requests

    monkeypatch.setattr(requests, "post", transport)
    static = {"http": "http://manual:8080", "https": "http://manual:8080"}
    parsed = _elc_parsed(monkeypatch)
    with pytest.raises(Exception):  # noqa: B017
        links.resolve_elc_links(
            parsed, user="u", api_key="k", selector=ProxySelector(static=static, force=True)
        )
    assert seen == [static]


def attempted_nothing(attempted) -> bool:
    return attempted == []
