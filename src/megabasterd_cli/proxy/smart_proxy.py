"""Smart proxy: per-request proxy selection with health tracking.

The Smart Proxy concept from the original MegaBasterd: when the user's IP is
rate-limited or blocked by MEGA, route some chunk requests through a configured
proxy or proxy pool. Healthy proxies are preferred; unhealthy ones are cooled
down for a short period.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from dataclasses import dataclass

import requests

log = logging.getLogger(__name__)


@dataclass
class ProxyEntry:
    url: str  # e.g. http://1.2.3.4:8080  or  socks5://user:pass@host:1080
    successes: int = 0
    failures: int = 0
    cooldown_until: float = 0
    last_used: float = 0

    @property
    def is_available(self) -> bool:
        return time.monotonic() >= self.cooldown_until


class SmartProxyPool:
    """Thread-safe pool of proxies with health tracking."""

    COOLDOWN_SECONDS = 60
    MAX_FAILURES = 3

    def __init__(self, proxies: list[str] | None = None, fallback_direct: bool = True):
        self._lock = threading.Lock()
        self._entries: list[ProxyEntry] = [ProxyEntry(url=p) for p in (proxies or [])]
        self.fallback_direct = fallback_direct

    # ------------------------------------------------------------------
    # Pool management
    # ------------------------------------------------------------------
    def add(self, url: str) -> None:
        with self._lock:
            if not any(e.url == url for e in self._entries):
                self._entries.append(ProxyEntry(url=url))

    def remove(self, url: str) -> bool:
        with self._lock:
            before = len(self._entries)
            self._entries = [e for e in self._entries if e.url != url]
            return len(self._entries) != before

    def list(self) -> list[ProxyEntry]:
        with self._lock:
            return list(self._entries)

    # ------------------------------------------------------------------
    # Selection and feedback
    # ------------------------------------------------------------------
    def pick(self) -> ProxyEntry | None:
        """Pick a random available proxy (preferring healthier ones)."""
        with self._lock:
            available = [e for e in self._entries if e.is_available]
            if not available:
                return None
            # Weight by success ratio (avoid div-by-zero)
            weights = []
            for e in available:
                total = e.successes + e.failures
                ratio = (e.successes + 1) / (total + 2)  # Laplace smoothing
                weights.append(ratio)
            choice = random.choices(available, weights=weights, k=1)[0]
            choice.last_used = time.monotonic()
            return choice

    def report_success(self, url: str) -> None:
        with self._lock:
            for e in self._entries:
                if e.url == url:
                    e.successes += 1
                    e.failures = max(0, e.failures - 1)
                    return

    def report_failure(self, url: str) -> None:
        with self._lock:
            for e in self._entries:
                if e.url == url:
                    e.failures += 1
                    if e.failures >= self.MAX_FAILURES:
                        e.cooldown_until = time.monotonic() + self.COOLDOWN_SECONDS
                        log.info("Proxy %s on cooldown for %ds", url, self.COOLDOWN_SECONDS)
                    return

    # ------------------------------------------------------------------
    # Convenience: requests adapter
    # ------------------------------------------------------------------
    def session_for_request(self) -> tuple[requests.Session, str | None]:
        """Return a (session, proxy_url) tuple. proxy_url may be None for direct."""
        entry = self.pick()
        session = requests.Session()
        if entry is None:
            return session, None
        session.proxies.update({"http": entry.url, "https": entry.url})
        return session, entry.url


def detect_blocked(response: requests.Response | None, exc: Exception | None) -> bool:
    """Heuristic: did this look like an ISP/CDN block?"""
    if exc is not None and isinstance(exc, (requests.ConnectionError, requests.Timeout)):
        return True
    return bool(response is not None and response.status_code in (403, 451, 503))
