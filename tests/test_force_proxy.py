"""Tests for force_smart_proxy enforcement on the API client + transferers.

The semantic: if force_proxy=True, direct connections must be refused even
when the SmartProxyPool is empty or absent. A manual `--proxy` (static
proxies) still satisfies the requirement.
"""

from __future__ import annotations

import pytest

from megabasterd_cli.core.api import MegaAPIClient
from megabasterd_cli.core.downloader import MegaDownloader
from megabasterd_cli.core.errors import MegaError, TransferError
from megabasterd_cli.proxy.smart_proxy import SmartProxyPool

# ---------------------------------------------------------------------------
# MegaAPIClient._request_proxies
# ---------------------------------------------------------------------------


def test_api_force_proxy_no_pool_no_static_refuses():
    client = MegaAPIClient(proxies=None, proxy_pool=None, force_proxy=True)
    with pytest.raises(MegaError, match="force_smart_proxy"):
        client._request_proxies()


def test_api_force_proxy_with_static_proxy_ok():
    client = MegaAPIClient(
        proxies={"http": "http://manual:8080", "https": "http://manual:8080"},
        proxy_pool=None,
        force_proxy=True,
    )
    result, picked = client._request_proxies()
    assert result == {"http": "http://manual:8080", "https": "http://manual:8080"}
    assert picked is None


def test_api_force_proxy_empty_pool_no_static_refuses():
    pool = SmartProxyPool()  # empty
    client = MegaAPIClient(proxy_pool=pool, force_proxy=True)
    with pytest.raises(MegaError, match="force_smart_proxy"):
        client._request_proxies()


def test_api_no_force_no_proxy_returns_direct():
    client = MegaAPIClient(proxies=None, proxy_pool=None, force_proxy=False)
    result, picked = client._request_proxies()
    assert result is None
    assert picked is None


def test_api_pool_pick_wins_over_static():
    pool = SmartProxyPool(["http://pool-pick:1111"])
    client = MegaAPIClient(
        proxies={"http": "http://manual:8080", "https": "http://manual:8080"},
        proxy_pool=pool,
        force_proxy=True,
    )
    result, picked = client._request_proxies()
    assert picked == "http://pool-pick:1111"
    assert result == {"http": "http://pool-pick:1111", "https": "http://pool-pick:1111"}


# ---------------------------------------------------------------------------
# MegaDownloader._proxies_for_request
# ---------------------------------------------------------------------------


def _make_downloader(**kwargs):
    return MegaDownloader(api=None, **kwargs)


def test_downloader_force_proxy_no_pool_no_static_refuses():
    dl = _make_downloader(proxies=None, proxy_pool=None, force_proxy=True)
    with pytest.raises(TransferError, match="force_smart_proxy"):
        dl._proxies_for_request()


def test_downloader_force_proxy_with_static_ok():
    dl = _make_downloader(
        proxies={"http": "http://manual:8080", "https": "http://manual:8080"},
        proxy_pool=None,
        force_proxy=True,
    )
    result, picked = dl._proxies_for_request()
    assert result == {"http": "http://manual:8080", "https": "http://manual:8080"}
    assert picked is None


def test_downloader_force_proxy_empty_pool_refuses():
    pool = SmartProxyPool()
    dl = _make_downloader(proxy_pool=pool, force_proxy=True)
    with pytest.raises(TransferError, match="force_smart_proxy"):
        dl._proxies_for_request()


def test_downloader_no_force_returns_direct():
    dl = _make_downloader(proxies=None, proxy_pool=None, force_proxy=False)
    result, picked = dl._proxies_for_request()
    assert result is None
    assert picked is None
