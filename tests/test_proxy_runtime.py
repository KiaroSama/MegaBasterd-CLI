"""Tests for the proxy/runtime helper that merges persisted pool + config."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from megabasterd_cli.config import Config
from megabasterd_cli.proxy import runtime
from megabasterd_cli.proxy.smart_proxy import SmartProxyPool


def _set_data_dir(tmp_path: Path):
    """Return a context manager that redirects proxy/runtime's data dir."""
    fake = tmp_path / "data"
    fake.mkdir()
    return patch.object(runtime, "data_dir", lambda: fake)


def test_effective_pool_returns_none_when_disabled(tmp_path: Path) -> None:
    cfg = Config(smart_proxy_enabled=False, smart_proxy_url="http://1.2.3.4:8080")
    with _set_data_dir(tmp_path):
        assert runtime.effective_pool(cfg) is None


def test_effective_pool_returns_none_when_empty(tmp_path: Path) -> None:
    cfg = Config(smart_proxy_enabled=True, smart_proxy_url=None)
    with _set_data_dir(tmp_path):
        assert runtime.effective_pool(cfg) is None


def test_effective_pool_merges_config_urls(tmp_path: Path) -> None:
    cfg = Config(
        smart_proxy_enabled=True,
        smart_proxy_url="http://1.2.3.4:8080, socks5://5.6.7.8:1080",
    )
    with _set_data_dir(tmp_path):
        pool = runtime.effective_pool(cfg)
        assert isinstance(pool, SmartProxyPool)
        urls = {e.url for e in pool.list()}
        assert urls == {"http://1.2.3.4:8080", "socks5://5.6.7.8:1080"}


def test_effective_pool_merges_persisted_and_config(tmp_path: Path) -> None:
    cfg = Config(
        smart_proxy_enabled=True,
        smart_proxy_url="http://config-proxy:1234",
    )
    with _set_data_dir(tmp_path):
        (tmp_path / "data" / "proxies.json").write_text(
            json.dumps({"proxies": ["http://disk-proxy:9999"]})
        )
        pool = runtime.effective_pool(cfg)
        assert pool is not None
        urls = {e.url for e in pool.list()}
        assert urls == {"http://disk-proxy:9999", "http://config-proxy:1234"}


def test_urls_from_config_separators() -> None:
    cfg = Config(smart_proxy_url="a, b;c\nd  e")
    assert runtime._urls_from_config(cfg) == ["a", "b", "c", "d", "e"]


def test_effective_pool_for_cmd_skipped_when_explicit_proxy(tmp_path: Path) -> None:
    cfg = Config(
        smart_proxy_enabled=True,
        smart_proxy_url="http://config-proxy:1234",
    )
    with _set_data_dir(tmp_path):
        # When --proxy was passed, the smart pool MUST be ignored
        assert runtime.effective_pool_for_cmd(cfg, "http://manual:8080") is None
        # When --proxy is None, behave like effective_pool
        pool = runtime.effective_pool_for_cmd(cfg, None)
        assert pool is not None
        assert {e.url for e in pool.list()} == {"http://config-proxy:1234"}


def test_effective_pool_deduplicates(tmp_path: Path) -> None:
    """A URL present in both the persisted pool and the config should only
    appear once in the merged pool."""
    cfg = Config(
        smart_proxy_enabled=True,
        smart_proxy_url="http://duplicate:1111",
    )
    with _set_data_dir(tmp_path):
        (tmp_path / "data" / "proxies.json").write_text(
            json.dumps({"proxies": ["http://duplicate:1111"]})
        )
        pool = runtime.effective_pool(cfg)
        assert pool is not None
        urls = [e.url for e in pool.list()]
        assert urls == ["http://duplicate:1111"]
