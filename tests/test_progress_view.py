"""Regression tests for MultiFileProgressView locking and speed measurement.

Locks in two fixes to the folder-download live view:

* ``update()``/``close()`` used to call ``Live.refresh()`` while holding the
  view lock. Rich's auto-refresh thread renders while holding Live's internal
  lock and re-enters ``__rich_console__`` (which needs the view lock), so the
  two lock orders inverted and the whole download UI could deadlock.
* Row meters were fed a 0-byte sample for queued rows at manifest time, so a
  resumed file's first progress report (which includes every byte downloaded
  in earlier sessions) registered as an instantaneous speed spike — the same
  inflated-resume-speed bug the downloader meter already fixed, reintroduced
  at the UI layer.
"""

from __future__ import annotations

import threading

import pytest

import megabasterd_cli.ui.progress as progress_module
from megabasterd_cli.ui.progress import MultiFileProgressView, ProgressFileState


class _ProbeLive:
    """Stand-in for rich.live.Live that records the deadlock precondition.

    On every ``refresh()`` a helper thread probes whether the view lock can be
    acquired; if it cannot, the caller entered ``refresh()`` while holding the
    view lock — exactly the ABBA inversion against Rich's refresh thread.
    """

    def __init__(self, renderable, **kwargs):
        self.renderable = renderable
        self.lock_held_during_refresh: list[bool] = []

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def refresh(self) -> None:
        view = self.renderable
        acquired = threading.Event()

        def probe() -> None:
            if view._lock.acquire(timeout=1.0):
                view._lock.release()
                acquired.set()

        thread = threading.Thread(target=probe)
        thread.start()
        thread.join(timeout=5.0)
        self.lock_held_during_refresh.append(not acquired.is_set())


class _FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.value = start

    def advance(self, seconds: float) -> None:
        self.value += seconds

    def __call__(self) -> float:
        return self.value


@pytest.fixture
def fake_clock(monkeypatch):
    clock = _FakeClock()
    monkeypatch.setattr(progress_module.time, "perf_counter", clock)
    return clock


@pytest.fixture
def probe_view(monkeypatch):
    monkeypatch.setattr(progress_module, "Live", _ProbeLive)
    view = MultiFileProgressView(title="test", min_interval=0.0)
    return view, view._live


def _row(completed: int, total: int, status: str) -> ProgressFileState:
    return ProgressFileState(key="a", name="a.bin", completed=completed, total=total, status=status)


def _update(view: MultiFileProgressView, row: ProgressFileState) -> None:
    view.update(
        [row],
        overall_completed=row.completed,
        overall_total=row.total,
        completed_items=0,
        total_items=1,
        force=True,
    )


class TestNoLockInversion:
    def test_update_refreshes_without_holding_view_lock(self, probe_view):
        view, live = probe_view
        _update(view, _row(completed=1, total=10, status="active"))
        assert live.lock_held_during_refresh == [False]

    def test_close_refreshes_without_holding_view_lock(self, probe_view):
        view, live = probe_view
        view.close(success=True)
        assert live.lock_held_during_refresh == [False]


class TestResumeSpeed:
    def test_queued_rows_do_not_seed_meters(self, probe_view):
        view, _ = probe_view
        _update(view, _row(completed=0, total=100, status="queued"))
        assert view._row_meters == {}

    def test_resumed_first_report_is_baseline_not_speed(self, fake_clock, probe_view):
        view, _ = probe_view
        total = 1_000_000_000
        _update(view, _row(completed=0, total=total, status="queued"))
        fake_clock.advance(2.0)
        # First real report: 900 MB of it was downloaded in EARLIER sessions.
        resumed = _row(completed=900_000_000, total=total, status="active")
        _update(view, resumed)
        view._render()
        assert resumed.speed == 0.0  # baseline sample, not a 450 MB/s spike
        assert view.overall_speed == 0.0
        # +1 MB over the next second must read ~1 MB/s.
        fake_clock.advance(1.0)
        progressed = _row(completed=901_000_000, total=total, status="active")
        _update(view, progressed)
        view._render()
        assert progressed.speed == pytest.approx(1_000_000, rel=0.1)
        assert view.overall_speed == pytest.approx(1_000_000, rel=0.1)

    def test_no_duplicate_overall_meter(self, probe_view):
        view, _ = probe_view
        assert not hasattr(view, "_overall_meter")
