"""force_smart_proxy holds through the REAL production call graph.

Unit-testing the resolver is not enough: `MegaDownloader.download_link()`
called `resolve_megacrypter_link()` without passing its policy, and the helper
silently substituted a permissive `ProxySelector()` - so force mode was off for
that hop and a direct socket was opened.

These tests drive the actual entry points and fail the moment an unproxied
request is attempted.
"""

from __future__ import annotations

import pytest

from megabasterd_cli.core.downloader import MegaDownloader
from megabasterd_cli.proxy.selector import ProxyRequiredError, ProxySelector
from megabasterd_cli.proxy.smart_proxy import SmartProxyPool

MC_URL = "mc://crypter.invalid/sometoken"
POOL_URL = "http://pool-proxy:3128"


@pytest.fixture()
def forbid_any_request(monkeypatch):
    """Every transport raises if used at all."""
    attempted: list[str] = []

    def guard(*args, **kwargs):
        target = args[0] if args else kwargs.get("url", "?")
        attempted.append(str(target))
        raise AssertionError(f"REQUEST ATTEMPTED IN FORCE MODE: {target}")

    import requests
    import requests.sessions

    for verb in ("get", "post", "head", "put", "request"):
        monkeypatch.setattr(requests, verb, guard)
    monkeypatch.setattr(requests.sessions.Session, "request", guard)
    return attempted


@pytest.fixture()
def record_proxied(monkeypatch):
    """Record the proxies of each request; fail if any goes out unproxied."""
    seen: list[dict] = []

    class _Resp:
        status_code = 200
        headers: dict = {}
        text = "{}"

        def json(self):
            return {"link": "https://mega.nz/file/ABCDEFGH#key"}

        def iter_content(self, chunk_size=65536):
            # The resolver now reads the reply as a bounded stream.
            yield b'{"link": "https://mega.nz/file/ABCDEFGH#key"}'

        def raise_for_status(self):
            return None

        def close(self):
            return None

    def guard(url, *args, **kwargs):
        proxies = kwargs.get("proxies")
        if not proxies:
            raise AssertionError(f"DIRECT (unproxied) request attempted to {url}")
        seen.append(proxies)
        return _Resp()

    import requests

    monkeypatch.setattr(requests, "post", guard)
    monkeypatch.setattr(requests, "get", guard)
    return seen


def _downloader(force: bool, pool_urls=()) -> MegaDownloader:
    return MegaDownloader(
        api=None,
        proxies=None,
        proxy_pool=SmartProxyPool(list(pool_urls)),
        force_proxy=force,
    )


def test_download_link_megacrypter_refuses_before_any_socket(forbid_any_request):
    """The regression: this path resolved the link with a permissive default."""
    downloader = _downloader(force=True)
    with pytest.raises(ProxyRequiredError):
        downloader.download_link(MC_URL, output_dir=None)
    assert forbid_any_request == [], f"force mode opened a socket: {forbid_any_request}"


def test_download_link_megacrypter_uses_the_selected_proxy(record_proxied):
    downloader = _downloader(force=True, pool_urls=[POOL_URL])
    # Resolution succeeds through the proxy and then fails later for unrelated
    # reasons (no real CDN); we only assert HOW the requests were routed.
    with pytest.raises(Exception):  # noqa: B017
        downloader.download_link(MC_URL, output_dir=None)
    assert record_proxied, "no request was made through the pool proxy"
    assert all(p == {"http": POOL_URL, "https": POOL_URL} for p in record_proxied)


def test_downloader_url_refresh_also_refuses(forbid_any_request):
    """The CDN-URL refresh closure must carry the same policy."""
    downloader = _downloader(force=True)
    with pytest.raises(ProxyRequiredError):
        downloader._proxies_for_request()
    assert forbid_any_request == []


# ---------------------------------------------------------------------------
# The root cause: a helper must never invent a permissive policy.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "call",
    [
        "resolve_elc_links",
        "decrypt_dlc_container",
        "get_megacrypter_info",
        "get_megacrypter_download_url",
        "resolve_megacrypter_link",
    ],
)
def test_link_services_require_an_explicit_policy(call, forbid_any_request):
    """Omitting the selector must be a programming error, not silent direct
    access. Otherwise one forgetful caller disables force mode."""
    from megabasterd_cli.core import link_services

    func = getattr(link_services, call)
    from megabasterd_cli.core.links import parse_link

    argument = parse_link(MC_URL) if "megacrypter" in call else ("A" * 200)
    if call == "resolve_elc_links":
        argument = parse_link("mega://elc?QUFB")
    with pytest.raises((ValueError, TypeError)) as caught:
        func(argument)
    assert (
        "selector" in str(caught.value).lower()
    ), f"{call} accepted a missing proxy policy: {caught.value}"
    assert forbid_any_request == []


def test_an_explicit_non_forced_policy_still_allows_direct(monkeypatch):
    """Non-force behavior is unchanged when the policy SAYS so explicitly."""
    seen = []

    class _Resp:
        status_code = 200
        headers: dict = {}
        text = "{}"

        def json(self):
            return {"link": "https://mega.nz/file/ABCDEFGH#key"}

        def iter_content(self, chunk_size=65536):
            # The resolver now reads the reply as a bounded stream.
            yield b'{"link": "https://mega.nz/file/ABCDEFGH#key"}'

        def raise_for_status(self):
            return None

        def close(self):
            return None

    def transport(url, *args, **kwargs):
        seen.append(kwargs.get("proxies"))
        return _Resp()

    import requests

    monkeypatch.setattr(requests, "post", transport)

    from megabasterd_cli.core.link_services import resolve_megacrypter_link
    from megabasterd_cli.core.links import parse_link

    resolve_megacrypter_link(parse_link(MC_URL), selector=ProxySelector(force=False))
    assert seen == [None]
