"""Runtime helpers for assembling the active SmartProxyPool.

Every CLI command that needs to honour the user's smart-proxy settings goes
through `effective_pool(cfg)` (or its `effective_pool_for_cmd(cfg, explicit_proxy)`
sibling for the download/stream paths that also accept a manual `--proxy`).

The active pool is the union of:

1. The persisted pool in `<data_dir>/proxies.json` (managed by `mb proxy add /
   fetch / import`).
2. Comma- or whitespace-separated URLs from the `smart_proxy_url` config key.

If both sources are empty, or `smart_proxy_enabled` is False, the helper
returns None — callers should treat that as "no smart-proxy routing".
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..config import Config, data_dir
from .smart_proxy import SmartProxyPool

_SPLIT_RE = re.compile(r"[\s,;]+")


def _pool_path() -> Path:
    return data_dir() / "proxies.json"


def _load_persisted_pool() -> SmartProxyPool:
    path = _pool_path()
    if not path.exists():
        return SmartProxyPool()
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        pool = SmartProxyPool()
        for url in data.get("proxies", []):
            pool.add(url)
        return pool
    except (json.JSONDecodeError, OSError):
        return SmartProxyPool()


def _urls_from_config(cfg: Config) -> list[str]:
    """Split smart_proxy_url into individual URLs.

    Accepts comma, semicolon, or whitespace separators so users can paste a
    flat proxy list straight into the config.
    """
    raw = cfg.smart_proxy_url
    if not raw:
        return []
    return [u for u in (s.strip() for s in _SPLIT_RE.split(raw)) if u]


def effective_pool(cfg: Config) -> SmartProxyPool | None:
    """Return the SmartProxyPool the command should use, or None.

    The pool merges the persisted on-disk pool with anything listed in
    `smart_proxy_url`. Returns None if smart proxy is disabled OR the merged
    pool ends up empty.
    """
    if not cfg.smart_proxy_enabled:
        return None
    pool = _load_persisted_pool()
    for url in _urls_from_config(cfg):
        pool.add(url)
    if not pool.list():
        return None
    return pool


def effective_pool_for_cmd(
    cfg: Config,
    explicit_proxy: str | None,
) -> SmartProxyPool | None:
    """Same as `effective_pool` but skipped when the user passed `--proxy`.

    Use this in commands where a manual --proxy flag should take precedence
    over the auto-rotating pool (`mb download --proxy ...`).
    """
    if explicit_proxy:
        return None
    return effective_pool(cfg)
