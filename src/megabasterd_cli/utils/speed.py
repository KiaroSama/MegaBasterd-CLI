"""Bandwidth limiting via token bucket."""

from __future__ import annotations

import threading
import time


class TokenBucket:
    """Thread-safe token-bucket rate limiter (bytes/sec).

    Call `consume(n_bytes)` before reading/writing; it blocks until enough
    tokens are available. Setting `rate=0` disables limiting.
    """

    def __init__(self, rate: float = 0, burst: float | None = None):
        self.rate = float(rate)
        self.burst = float(burst) if burst is not None else max(self.rate, 1.0)
        self._tokens = self.burst
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def set_rate(self, rate: float) -> None:
        with self._lock:
            self.rate = float(rate)
            self.burst = max(self.burst, self.rate)

    def consume(self, amount: int) -> None:
        """Block until `amount` tokens (bytes) are available."""
        if self.rate <= 0:
            return  # Unlimited
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
                if self._tokens >= amount:
                    self._tokens -= amount
                    return
                deficit = amount - self._tokens
                wait = deficit / self.rate
            time.sleep(min(wait, 1.0))


class NoOpLimiter:
    """No-op limiter when rate limiting is disabled."""

    def consume(self, amount: int) -> None:
        pass

    def set_rate(self, rate: float) -> None:
        pass


def make_limiter(kbps: float) -> TokenBucket | NoOpLimiter:
    """Construct a rate limiter; returns NoOpLimiter when kbps <= 0."""
    if kbps <= 0:
        return NoOpLimiter()
    return TokenBucket(rate=kbps * 1024)
