"""Regression tests for the TokenBucket rate limiter.

The historical bug: `consume(amount)` waited for `_tokens >= amount` while
`_tokens` is capped at `burst`, so any request larger than the burst capacity
(e.g. a 1 MiB upload chunk against a small configured rate) hung forever.
"""

from __future__ import annotations

import threading
import time

from megabasterd_cli.utils.speed import NoOpLimiter, TokenBucket, make_limiter


class FakeClock:
    """Deterministic clock: sleeping advances virtual time."""

    def __init__(self) -> None:
        self.now = 0.0
        self._lock = threading.Lock()

    def time(self) -> float:
        with self._lock:
            return self.now

    def sleep(self, seconds: float) -> None:
        assert seconds >= 0
        with self._lock:
            self.now += seconds


def _run_with_timeout(fn, timeout: float = 10.0) -> None:
    """Run fn on a thread and fail the test instead of hanging forever."""
    done = threading.Event()
    error: list[BaseException] = []

    def _target() -> None:
        try:
            fn()
        except BaseException as exc:  # noqa: BLE001 - surfaced below
            error.append(exc)
        finally:
            done.set()

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    assert done.wait(timeout), "consume() did not make forward progress (hang)"
    if error:
        raise error[0]


def test_amount_larger_than_burst_completes() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate=1024, burst=512, clock=clock.time, sleeper=clock.sleep)
    _run_with_timeout(lambda: bucket.consume(4096))
    # 512 free burst tokens, remaining 3584 accrue at 1024/s.
    assert clock.time() >= 3.0


def test_low_rate_64k_download_block_progresses() -> None:
    clock = FakeClock()
    # 10 KB/s limit: burst == rate == 10240 < 65536 block.
    bucket = TokenBucket(rate=10 * 1024, clock=clock.time, sleeper=clock.sleep)
    _run_with_timeout(lambda: bucket.consume(64 * 1024))
    assert clock.time() >= 5.0


def test_low_rate_1mib_upload_chunk_progresses() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate=64 * 1024, clock=clock.time, sleeper=clock.sleep)
    _run_with_timeout(lambda: bucket.consume(1024 * 1024))
    # (1 MiB - 64 KiB burst) / 64 KiB/s = 15 s of virtual waiting.
    assert clock.time() >= 14.0


def test_concurrent_consumers_share_aggregate_cap() -> None:
    rate = 2 * 1024 * 1024  # 2 MiB/s shared cap
    bucket = TokenBucket(rate=rate, burst=128 * 1024)
    per_thread = 512 * 1024
    threads = [
        threading.Thread(target=lambda: bucket.consume(per_thread), daemon=True) for _ in range(4)
    ]
    start = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
        assert not t.is_alive(), "consumer hung"
    elapsed = time.monotonic() - start
    # 2 MiB total minus the 128 KiB initial burst at 2 MiB/s ~= 0.94 s.
    expected = (4 * per_thread - 128 * 1024) / rate
    assert elapsed >= expected * 0.5
    assert elapsed <= expected * 4 + 1.0


def test_unlimited_mode_never_blocks() -> None:
    calls: list[float] = []
    bucket = TokenBucket(rate=0, sleeper=calls.append)
    bucket.consume(10**9)
    assert calls == []
    # Reverted to the pre-regression assertion: make_limiter(0) returning a
    # NoOpLimiter is the 1.x contract, and this line was edited to match the
    # behaviour change rather than the behaviour being kept.
    limiter = make_limiter(0)
    assert isinstance(limiter, NoOpLimiter)
    limiter.consume(10**9)


def test_zero_and_negative_amounts_are_safe() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate=1024, clock=clock.time, sleeper=clock.sleep)
    bucket.consume(0)
    bucket.consume(-5)
    assert clock.time() == 0.0


def test_set_rate_mid_consume_is_safe() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate=1024, burst=512, clock=clock.time, sleeper=clock.sleep)

    def sleeper(seconds: float) -> None:
        clock.sleep(seconds)
        # Simulate a runtime rate change during the wait loop.
        bucket.set_rate(0)

    bucket._sleep = sleeper
    _run_with_timeout(lambda: bucket.consume(10 * 1024 * 1024))
    # Rate was set to 0 (unlimited) after the first wait; consume() must return.


def test_set_rate_lower_keeps_bucket_consistent() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate=4096, clock=clock.time, sleeper=clock.sleep)
    bucket.set_rate(512)
    assert bucket._tokens <= bucket.burst
    _run_with_timeout(lambda: bucket.consume(8 * 1024))
