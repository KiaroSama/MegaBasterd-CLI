"""The single per-request proxy-selection authority.

Every outbound HTTP request in this project — API calls, chunk transfers,
streaming CDN reads, MegaCrypter/DLC/ELC resolution, proxy-list fetches —
picks its proxies here. Selection lived in three near-identical private
methods before (`MegaAPIClient`, `MegaDownloader`, `MegaUploader`) while
streaming and link resolution had none at all, so `force_smart_proxy` was
silently unenforced on those paths.

Enforced invariant:

    When force mode is on, `select()` NEVER returns a direct (proxy-less)
    request configuration. If no proxy is available it raises
    ProxyRequiredError before any socket is opened, and there is no
    fallback to direct after a proxy failure.
"""

from __future__ import annotations

from ..core.errors import NonRetryableTransferError


class ProxyRequiredError(NonRetryableTransferError):
    """force_smart_proxy is on but no usable proxy is available.

    A TransferError (and therefore a MegaError) so every existing
    command-level handler already reports it as a normal transfer failure —
    non-zero exit with a sanitized message, never a traceback.

    Non-retryable: the pool's state cannot change because we asked again, so
    replaying this decision only burns the retry budget in backoff.
    """


class ProxySelector:
    """Per-request proxy decision shared by every network consumer.

    Precedence, unchanged from the original per-class copies:
      1. a pick from the SmartProxyPool, when one is configured;
      2. the static proxies dict (a manual ``--proxy``);
      3. refuse when force mode is on, otherwise go direct.
    """

    __slots__ = ("pool", "static", "force")

    def __init__(
        self,
        pool=None,  # SmartProxyPool | None
        static: dict[str, str] | None = None,
        force: bool = False,
    ):
        self.pool = pool
        self.static = static or None
        self.force = force

    @classmethod
    def from_config(cls, cfg, explicit_proxy: str | None = None) -> ProxySelector:
        """Build the selector a command should use.

        An explicit ``--proxy`` wins over the rotating pool (matching
        `effective_pool_for_cmd`), but force mode still applies: if neither a
        pool pick nor a static proxy is available, requests are refused.
        """
        from .runtime import effective_pool_for_cmd

        static = {"http": explicit_proxy, "https": explicit_proxy} if explicit_proxy else None
        return cls(
            pool=effective_pool_for_cmd(cfg, explicit_proxy),
            static=static,
            force=bool(getattr(cfg, "force_smart_proxy", False)),
        )

    def select(self) -> tuple[dict[str, str] | None, str | None]:
        """Return (proxies_kwarg, picked_pool_url_for_reporting).

        Raises ProxyRequiredError instead of returning a direct configuration
        whenever force mode is on and nothing is available.
        """
        if self.pool is not None:
            entry = self.pool.pick()
            if entry is not None:
                return {"http": entry.url, "https": entry.url}, entry.url
        if self.static:
            return self.static, None
        if self.force:
            raise ProxyRequiredError(
                message="force_smart_proxy is on but no proxy is available "
                "(pool empty or exhausted, and no --proxy was given); "
                "refusing to connect directly"
            )
        return None, None

    def report_success(self, picked: str | None) -> None:
        if picked and self.pool is not None:
            self.pool.report_success(picked)

    def report_failure(self, picked: str | None) -> None:
        if picked and self.pool is not None:
            self.pool.report_failure(picked)
