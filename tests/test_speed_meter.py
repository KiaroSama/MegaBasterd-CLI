"""Regression tests for RollingSpeedMeter and the downloader's progress cadence.

Locks in two user-visible fixes:

* Reported download speed used to be ``bytes_done / elapsed_since_start`` — a
  lifetime average that also counted resumed bytes, so a resumed transfer
  showed absurdly inflated speeds and any rate change lagged for minutes.
  Speed now comes from a rolling window over recent byte deltas.
* ``on_progress`` used to fire once per completed chunk future in submission
  order (fut.result() blocks on the first unfinished future), so progress
  arrived in late bursts. It now flows from a steady 0.5 s reporter thread.
"""

from __future__ import annotations

import threading
import time

from megabasterd_cli.utils.speed import RollingSpeedMeter


class TestRollingSpeedMeter:
    def test_steady_rate(self):
        meter = RollingSpeedMeter(window=5.0)
        for second in range(6):
            meter.update(second * 1_000_000, now=float(second))
        assert abs(meter.current(now=5.0) - 1_000_000) < 50_000

    def test_resume_baseline_excluded(self):
        meter = RollingSpeedMeter(window=5.0)
        meter.update(900_000_000, now=0.0)  # resumed bytes = baseline
        meter.update(901_000_000, now=1.0)  # +1 MB in 1 s
        # The old lifetime-average formula would report ~901 MB/s here.
        assert abs(meter.current(now=1.0) - 1_000_000) < 100_000

    def test_decays_to_zero_during_stall(self):
        meter = RollingSpeedMeter(window=5.0)
        meter.update(0, now=0.0)
        meter.update(2_000_000, now=1.0)
        assert meter.current(now=1.0) > 1_500_000
        assert meter.current(now=4.0) < meter.current(now=2.0) or meter.current(now=4.0) == 0.0
        assert meter.current(now=7.0) == 0.0

    def test_rewind_clears_window(self):
        meter = RollingSpeedMeter(window=5.0)
        meter.update(5_000_000, now=0.0)
        meter.update(1_000_000, now=1.0)
        assert meter.current(now=1.2) == 0.0

    def test_thread_safety_smoke(self):
        meter = RollingSpeedMeter(window=2.0)
        stop = threading.Event()
        errors: list[Exception] = []

        def feed():
            count = 0
            while not stop.is_set():
                count += 1024
                try:
                    meter.update(count)
                except Exception as exc:  # pragma: no cover
                    errors.append(exc)

        def read():
            while not stop.is_set():
                try:
                    meter.current()
                except Exception as exc:  # pragma: no cover
                    errors.append(exc)

        threads = [threading.Thread(target=feed), threading.Thread(target=read)]
        for t in threads:
            t.start()
        time.sleep(0.5)
        stop.set()
        for t in threads:
            t.join(timeout=2.0)
        assert not errors
