"""Bandwidth limiting via token bucket, plus rolling transfer-speed measurement."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable


class RollingSpeedMeter:
    """Stable bytes/sec from cumulative byte samples over a sliding window.

    Feed the latest *cumulative* byte count via :meth:`update` whenever bytes
    land; read the display rate via :meth:`current`, which measures
    ``delta_bytes / (now - oldest_sample)`` so the rate decays smoothly to 0
    while no new bytes arrive (instead of freezing at the last value) and the
    first sample acts as the baseline (resumed bytes never inflate the rate).
    """

    def __init__(self, window: float = 5.0) -> None:
        self.window = max(1.0, float(window))
        self.samples: deque[tuple[float, int]] = deque()
        self.speed = 0.0
        self._lock = threading.Lock()

    def update(self, byte_count: int, now: float | None = None) -> float:
        now = time.monotonic() if now is None else now
        byte_count = max(0, int(byte_count or 0))
        with self._lock:
            if self.samples and byte_count < self.samples[-1][1]:
                self.samples.clear()
                self.speed = 0.0
            self.samples.append((now, byte_count))
            while len(self.samples) > 1 and now - self.samples[0][0] > self.window:
                self.samples.popleft()
            if len(self.samples) >= 2:
                elapsed = self.samples[-1][0] - self.samples[0][0]
                delta = self.samples[-1][1] - self.samples[0][1]
                if elapsed >= 0.25 and delta >= 0:
                    self.speed = delta / max(elapsed, 1e-6)
            return self.speed

    def current(self, now: float | None = None) -> float:
        now = time.monotonic() if now is None else now
        with self._lock:
            while len(self.samples) > 1 and now - self.samples[0][0] > self.window:
                self.samples.popleft()
            if len(self.samples) < 2:
                return 0.0
            elapsed = now - self.samples[0][0]
            delta = self.samples[-1][1] - self.samples[0][1]
            if elapsed < 0.25 or delta < 0:
                return self.speed
            return delta / max(elapsed, 1e-6)


class TokenBucket:
    """Thread-safe token-bucket rate limiter (bytes/sec).

    Call `consume(n_bytes)` before reading/writing; it blocks until enough
    tokens are available. Setting `rate=0` disables limiting. Requests larger
    than the burst capacity are drained incrementally in bucket-sized pieces,
    so every positive amount makes forward progress (a request can never wait
    for more tokens than the bucket can physically hold). `clock` and
    `sleeper` exist for deterministic tests.
    """

    def __init__(
        self,
        rate: float = 0,
        burst: float | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ):
        self.rate = float(rate)
        self.burst = float(burst) if burst is not None else max(self.rate, 1.0)
        self._clock = clock
        self._sleep = sleeper
        self._tokens = self.burst
        self._last = self._clock()
        self._lock = threading.Lock()

    def set_rate(self, rate: float) -> None:
        with self._lock:
            self.rate = float(rate)
            self.burst = max(self.burst, self.rate)
            # Never leave more tokens than the bucket can hold.
            self._tokens = min(self._tokens, self.burst)

    def consume(self, amount: int) -> None:
        """Block until `amount` tokens (bytes) have been drained."""
        remaining = float(amount or 0)
        if remaining <= 0:
            return
        while True:
            with self._lock:
                if self.rate <= 0:
                    return  # Unlimited (covers rates changed at runtime too)
                now = self._clock()
                elapsed = max(0.0, now - self._last)
                self._last = now
                self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
                take = min(remaining, self._tokens)
                self._tokens -= take
                remaining -= take
                if remaining <= 0:
                    return
                # Wait for at most one bucket's worth of the outstanding bytes;
                # larger requests drain over multiple rounds.
                wait = min(remaining, self.burst) / self.rate
            self._sleep(min(wait, 1.0))


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
