"""One MegaAPIClient factory for every command module.

Nine command sites built the client by hand and had to remember the same
three proxy settings each time. They differ only in whether a static
``--proxy`` dict, a pre-built pool, or a custom user agent applies.
"""

from __future__ import annotations

from typing import Any

from ..config import Config
from ..core.api import MegaAPIClient
from ..proxy.runtime import effective_pool

# Sentinel, because `None` is itself a meaningful pool value: an explicit
# `--proxy` deliberately suppresses the rotating pool, and that must not be
# confused with "the caller didn't say, derive it from cfg".
_FROM_CONFIG: Any = object()


def api_for(
    cfg: Config,
    *,
    proxies: dict[str, str] | None = None,
    proxy_pool: Any = _FROM_CONFIG,
    user_agent: str | None = None,
) -> MegaAPIClient:
    """Build a MegaAPIClient that honours the user's smart-proxy settings.

    Pass ``proxy_pool`` explicitly when the caller already holds a pool it
    shares with a downloader/uploader (one pool per command, not per client),
    or when a static ``--proxy`` means there should be no pool at all.
    """
    return MegaAPIClient(
        timeout=cfg.timeout_seconds,
        proxies=proxies,
        proxy_pool=effective_pool(cfg) if proxy_pool is _FROM_CONFIG else proxy_pool,
        force_proxy=cfg.force_smart_proxy,
        user_agent=user_agent,
    )
