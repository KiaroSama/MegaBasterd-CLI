"""Unified transfer-progress controller: lifecycle, Elapsed, aggregation.

Covers phase requirements:
- every item ends in exactly one terminal state (complete/failed/canceled/
  skipped) and nothing stays visually active after close();
- Elapsed comes from one monotonic clock owned by the view, keeps advancing
  while producers are silent, is frozen exactly at terminal state, and is
  shown even on narrow terminals;
- the same controller/renderer serves single and multi transfer modes.
"""

from __future__ import annotations

import time

import pytest

import megabasterd_cli.ui.progress as progress_module
from megabasterd_cli.ui.progress import MultiFileProgressView
from megabasterd_cli.ui.transfer_progress import TransferProgress, redact_link


class _NoOpLive:
    def __init__(self, renderable, **kwargs):
        self.renderable = renderable

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def refresh(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _stub_live(monkeypatch):
    monkeypatch.setattr(progress_module, "Live", _NoOpLive)


class _RecordingView:
    """Minimal fake renderer that records controller pushes."""

    def __init__(self):
        self.updates: list[dict] = []
        self.closed: list[bool] = []

    def update(self, file_states, **kwargs):
        self.updates.append({"states": file_states, **kwargs})

    def close(self, success=True):
        self.closed.append(success)


def _controller(**kwargs) -> tuple[TransferProgress, _RecordingView]:
    view = _RecordingView()
    tp = TransferProgress(title="t", view_factory=lambda: view, **kwargs)
    return tp, view


def test_every_item_ends_in_exactly_one_terminal_state():
    tp, view = _controller()
    done = tp.add_item("a.bin", 100)
    failed = tp.add_item("b.bin", 100)
    leftover = tp.add_item("c.bin", 100)
    finished_bytes = tp.add_item("d.bin", 100)

    tp.update_item(done, 100, 100)
    tp.finish_item(done, "complete")
    tp.update_item(failed, 10, 100)
    tp.finish_item(failed, "failed")
    tp.update_item(finished_bytes, 100, 100)  # bytes done but never finished
    tp.close(success=False)

    statuses = tp.statuses()
    assert statuses[done] == "complete"
    assert statuses[failed] == "failed"
    assert statuses[leftover] == "canceled", "leftover items must not stay active"
    assert statuses[finished_bytes] == "complete", "byte-complete items finalize as complete"
    assert view.closed == [False]
    # finish_item after close must not resurrect anything.
    tp.finish_item(leftover, "complete")
    assert tp.statuses()[leftover] == "canceled"


def test_terminal_states_are_immutable_and_validated():
    tp, _ = _controller()
    item = tp.add_item("a.bin", 10)
    tp.finish_item(item, "complete")
    tp.finish_item(item, "failed")  # ignored: already terminal
    assert tp.statuses()[item] == "complete"
    with pytest.raises(ValueError):
        tp.finish_item(item, "running")


def test_overall_aggregation_and_failed_counts():
    tp, view = _controller()
    a = tp.add_item("a.bin", 100)
    b = tp.add_item("b.bin", 300)
    tp.update_item(a, 50, 100)
    tp.update_item(b, 100, 300)
    tp.finish_item(a, "failed")
    last = view.updates[-1]
    assert last["overall_completed"] == 150
    assert last["overall_total"] == 400
    assert last["failed_items"] == 1
    assert last["total_items"] == 2
    assert tp.failed_count() == 1


def test_quiet_mode_creates_no_view():
    view_calls = []
    tp = TransferProgress(title="t", quiet=True, view_factory=lambda: view_calls.append(1))
    item = tp.add_item("a.bin", 10)
    tp.update_item(item, 5, 10)
    tp.finish_item(item)
    tp.close()
    assert view_calls == [], "quiet mode must not build a live view"
    assert tp.statuses()[item] == "complete"


def test_mixed_direction_prefixes_names():
    tp, view = _controller(direction="mixed")
    tp.add_item("up.bin", 1, direction="upload")
    tp.add_item("down.bin", 1, direction="download")
    names = [s.name for s in view.updates[-1]["states"]]
    assert names == ["↑ up.bin", "↓ down.bin"]


def test_redact_link_strips_key_material():
    url = "https://mega.nz/folder/PUBLICID0#FAKEKEYFAKEKEYFAKEKEY"
    assert redact_link(url) == "https://mega.nz/folder/PUBLICID0#<key>"
    assert redact_link("plain") == "plain"


def test_elapsed_is_wall_clock_and_freezes_at_close(monkeypatch):
    view = MultiFileProgressView(title="t")
    view.started_at = time.perf_counter() - 100.0  # simulate 100 s of runtime
    # Elapsed must render even on narrow widths.
    text = view._stats_text(0, None, 0.0, width=80, include_elapsed=True)
    rendered = text.plain
    assert "Elapsed" in rendered
    assert "01:4" in rendered  # ~1:40, independent of bytes/speed/percent
    view.close(success=True)
    frozen = view.finished_at
    assert frozen is not None
    time.sleep(0.05)
    text2 = view._stats_text(0, None, 0.0, width=80, include_elapsed=True)
    assert text2.plain == rendered, "Elapsed must stop exactly at terminal state"


def test_elapsed_advances_without_producer_updates():
    view = MultiFileProgressView(title="t")
    first = view._stats_text(0, None, 0.0, width=100, include_elapsed=True).plain
    time.sleep(1.1)
    # No update() calls in between: the renderer alone must advance Elapsed.
    second = view._stats_text(0, None, 0.0, width=100, include_elapsed=True).plain
    assert first != second


def test_visible_rows_are_bounded_for_huge_folders():
    tp, view = _controller()
    keys = [tp.add_item(f"f{i:03d}.bin", 10) for i in range(50)]
    tp.update_item(keys[40], 5, 10)  # one active row
    inner = MultiFileProgressView(title="t")
    inner.file_states = view.updates[-1]["states"]
    visible, hidden = inner._visible_rows()
    assert len(visible) == progress_module.MAX_VISIBLE_FILE_ROWS
    assert hidden == 50 - progress_module.MAX_VISIBLE_FILE_ROWS
    shown = {pair[1].name for pair in visible}
    assert "f040.bin" in shown, "active rows win a visible slot"


def test_failed_item_makes_overall_failed_without_exception():
    """MF4: per-item errors are caught by commands, so the context exits
    cleanly — the overall state must still be Failed."""
    tp, view = _controller()
    ok = tp.add_item("a.bin", 10)
    bad = tp.add_item("b.bin", 10)
    tp.update_item(ok, 10, 10)
    tp.finish_item(ok, "complete")
    tp.finish_item(bad, "failed")
    with tp:
        pass  # clean exit, no exception
    assert tp.final_success() is False
    assert view.closed == [False]
    assert view.updates[-1]["status"] == "Failed"


def test_all_complete_overall_complete():
    tp, view = _controller()
    a = tp.add_item("a.bin", 10)
    tp.update_item(a, 10, 10)
    tp.finish_item(a, "complete")
    tp.close(success=True)
    assert tp.final_success() is True
    assert view.closed == [True]
    assert view.updates[-1]["status"] == "Complete"


def test_explicit_user_skip_alone_stays_successful():
    tp, view = _controller()
    a = tp.add_item("a.bin", 10)
    tp.finish_item(a, "skipped")
    tp.close(success=True)
    assert tp.final_success() is True
    assert view.closed == [True]


def test_unfinished_active_item_prevents_overall_complete():
    tp, view = _controller()
    a = tp.add_item("a.bin", 10)
    tp.update_item(a, 3, 10)  # still active at close time
    tp.close(success=True)
    assert tp.statuses()[a] == "canceled"
    assert tp.final_success() is False, "an incomplete item must not read as success"
    assert view.closed == [False]


def test_close_is_idempotent_and_never_unfails():
    tp, view = _controller()
    a = tp.add_item("a.bin", 10)
    tp.finish_item(a, "failed")
    tp.close(success=True)
    first = tp.final_success()
    tp.close(success=True)  # repeated close: no-op
    assert tp.final_success() is first is False
    assert view.closed == [False], "close must run the view finalization once"


def test_canceled_and_skipped_render_labels():
    view = MultiFileProgressView(title="t")
    canceled = view._stats_text(0, 10, 0.0, width=100, include_elapsed=False, status="canceled")
    skipped = view._stats_text(0, 10, 0.0, width=100, include_elapsed=False, status="skipped")
    assert "Canceled" in canceled.plain
    assert "Skipped" in skipped.plain
