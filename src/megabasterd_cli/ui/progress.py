"""Rich-based progress bars for transfers."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from rich.console import Group
from rich.live import Live
from rich.text import Text

from ..utils.helpers import format_eta
from ..utils.speed import RollingSpeedMeter
from .theme import make_console

PROGRESS_SEPARATOR = "=" * 120

# Huge folders: cap the per-file rows painted each frame (totals still cover
# every file); active rows win, then queued, then finished ones.
MAX_VISIBLE_FILE_ROWS = 12


@dataclass
class ProgressFileState:
    """One file row in a shared multi-file progress view."""

    key: str
    name: str
    completed: int = 0
    total: int | None = None
    speed: float | None = 0.0
    status: str = "queued"


class MultiFileProgressView:
    """Live progress with one overall row and one row per file."""

    def __init__(
        self,
        title: str,
        details: list[str] | None = None,
        item_label: str = "files",
        min_interval: float = 0.5,
    ) -> None:
        self.title = title
        self.details = list(details or [])
        self.item_label = item_label
        self.min_interval = min_interval
        self.started_at = time.perf_counter()
        # Set exactly once at terminal state; freezes the Elapsed display.
        self.finished_at: float | None = None
        self.last_render = 0.0
        self.overall_completed = 0
        self.overall_total: int | None = None
        self.overall_speed = 0.0
        self.completed_items = 0
        self.total_items = 0
        self.failed_items = 0
        self.status = "Starting"
        self.file_states: list[ProgressFileState] = []
        self._lock = threading.RLock()
        # View-owned speed measurement: one rolling meter per file row. Speeds
        # and ETA are computed at RENDER time from these meters, so they decay
        # to 0 during a stall instead of freezing at the last producer-supplied
        # value. The overall speed is the sum of the row meters (or a fresh
        # producer-supplied hint), so there is no second meter to drift.
        self._row_meters: dict[str, RollingSpeedMeter] = {}
        self._backend_speed: float | None = None
        self._backend_speed_at = 0.0
        self._console = make_console(color_system="truecolor")
        # Pass SELF as the renderable: Rich re-invokes __rich_console__ on
        # every auto-refresh (4/s), so Elapsed / ETA / speed keep moving even
        # while the producer is silent (Rich's Live runs its own refresh
        # thread). A pre-built static Group would freeze between updates.
        self._live = Live(
            self,
            console=self._console,
            refresh_per_second=4,
            transient=False,
        )
        self._live.start()

    def __rich_console__(self, console, options):  # pragma: no cover - Rich hook
        with self._lock:
            yield self._render()

    def update(
        self,
        file_states: list[ProgressFileState],
        overall_completed: int,
        overall_total: int | None,
        completed_items: int,
        total_items: int,
        failed_items: int = 0,
        status: str = "Downloading",
        overall_speed: float | None = None,
        force: bool = False,
    ) -> None:
        with self._lock:
            now = time.perf_counter()
            self.file_states = list(file_states)
            self.overall_completed = max(0, int(overall_completed or 0))
            self.overall_total = int(overall_total) if overall_total is not None else None
            if self.overall_total is not None and self.overall_completed > self.overall_total:
                self.overall_total = self.overall_completed
            self.completed_items = max(0, int(completed_items or 0))
            self.total_items = max(0, int(total_items or 0))
            self.failed_items = max(0, int(failed_items or 0))
            self.status = status
            # Feed the view-owned meters with this frame's cumulative bytes.
            # Queued rows are skipped: they carry no transfer data yet, and a
            # 0-byte sample would turn a resumed file's FIRST report (which
            # includes every previously-downloaded byte) into a huge fake
            # speed spike. By feeding only reporting rows, the meter's first
            # sample is the resume baseline and is excluded from the rate.
            live_keys = {state.key for state in self.file_states}
            for stale_key in [key for key in self._row_meters if key not in live_keys]:
                self._row_meters.pop(stale_key, None)
            for state in self.file_states:
                if state.status == "queued":
                    continue
                meter = self._row_meters.setdefault(state.key, RollingSpeedMeter(window=5.0))
                meter.update(max(0, int(state.completed or 0)), now)
            # A producer-reported overall speed is authoritative while fresh;
            # render falls back to the summed row meters when it goes stale.
            if overall_speed is not None and overall_speed >= 0:
                self._backend_speed = float(overall_speed)
                self._backend_speed_at = now
            should_refresh = force or now - self.last_render >= self.min_interval
            if should_refresh:
                self.last_render = now
        # Refresh OUTSIDE self._lock. Rich's auto-refresh thread renders while
        # holding Live's internal lock and re-enters __rich_console__, which
        # needs self._lock; calling refresh() (which takes Live's lock) while
        # holding self._lock is an ABBA inversion that deadlocks the UI.
        if should_refresh:
            self._live.refresh()

    def close(self, success: bool = True) -> None:
        with self._lock:
            if self.finished_at is None:
                self.finished_at = time.perf_counter()
            self.status = "Complete" if success else "Failed"
            if success and self.overall_total is not None:
                self.overall_completed = max(self.overall_completed, self.overall_total)
        # Outside self._lock for the same lock-ordering reason as update().
        self._live.refresh()
        self._live.stop()
        print()

    def _render(self) -> Group:
        # Speeds are measured HERE, at render time, by the view's own meters:
        # Rich's auto-refresh calls this ~4x/s, so between producer updates the
        # elapsed clock ticks, speeds decay during stalls, and ETA follows.
        now = time.perf_counter()
        for state in self.file_states:
            if state.status == "active":
                meter = self._row_meters.get(state.key)
                state.speed = meter.current(now) if meter is not None else 0.0
        if self._backend_speed is not None and now - self._backend_speed_at <= 2.5:
            self.overall_speed = self._backend_speed
        else:
            self.overall_speed = sum(meter.current(now) for meter in self._row_meters.values())
        width = max(70, min(140, int(getattr(self._console, "width", 100) or 100)))
        title_style = "#ff5f94" if self.status != "Failed" else "bold red"
        lines: list[Text] = [Text(_shorten_middle(self.title, width), style=title_style), Text("")]
        for detail in self.details:
            if not detail:
                lines.append(Text(""))
                continue
            style = "bold #70ffbf" if detail.startswith("Backend:") else "bold #9ed8ff"
            lines.append(Text(_shorten_middle(detail, width), style=style))
        if self.details:
            lines.append(Text(PROGRESS_SEPARATOR[:width], style="bold #70ffbf"))
            lines.append(Text(""))
        lines.append(Text("Overall", style="bold #7cf7ff"))
        lines.append(
            self._stats_text(
                self.overall_completed,
                self.overall_total,
                self.overall_speed,
                width,
                include_elapsed=True,
            )
        )
        visible, hidden = self._visible_rows()
        if visible:
            lines.append(Text(""))
        for index, (row_number, state) in enumerate(visible, 1):
            name_style = self._state_style(state.status)
            prefix = f"File {row_number:02d}: "
            lines.append(
                Text(
                    prefix + _shorten_middle(state.name, max(10, width - len(prefix))),
                    style=name_style,
                )
            )
            lines.append(
                self._stats_text(
                    state.completed,
                    state.total,
                    state.speed,
                    width,
                    include_elapsed=False,
                    status=state.status,
                )
            )
            if index < len(visible):
                lines.append(Text(""))
        if hidden:
            lines.append(Text(f"(+{hidden} more {self.item_label})", style="yellow"))
        return Group(*lines)

    def _visible_rows(self) -> tuple[list[tuple[int, ProgressFileState]], int]:
        """Bound the painted rows for huge folders without losing totals."""
        numbered = list(enumerate(self.file_states, 1))
        if len(numbered) <= MAX_VISIBLE_FILE_ROWS:
            return numbered, 0
        rank = {"active": 0, "queued": 1}
        ordered = sorted(numbered, key=lambda pair: (rank.get(pair[1].status, 2), pair[0]))
        visible = sorted(ordered[:MAX_VISIBLE_FILE_ROWS], key=lambda pair: pair[0])
        return visible, len(numbered) - MAX_VISIBLE_FILE_ROWS

    def _stats_text(
        self,
        completed: int,
        total: int | None,
        speed: float | None,
        width: int,
        include_elapsed: bool,
        status: str = "active",
    ) -> Text:
        percent = (completed / total * 100.0) if total else 0.0
        percent = max(0.0, min(100.0, percent))
        # Elapsed is never hidden; on narrow terminals the bar shrinks instead.
        bar_width = max(12, min(32, width - 96))
        remaining = (total - completed) if total else 0
        done = status in {"complete", "downloaded", "resumed"} or bool(total and completed >= total)
        failed = status in {"failed", "error"}
        stopped = status in {"canceled", "skipped"}
        if done:
            eta = speed_label = "Done"
        elif failed:
            eta = speed_label = "Failed"
        elif stopped:
            eta = speed_label = status.capitalize()
        else:
            eta = format_eta(remaining / speed) if total and speed and speed > 1 else "--:--"
            speed_label = _format_speed(speed)
        speed_style = (
            "bold green"
            if done
            else "bold red" if failed else "yellow" if stopped else "bold #39ff6a"
        )
        eta_style = (
            "bold green" if done else "bold red" if failed else "yellow" if stopped else "#ff8a1f"
        )
        text = Text()
        text.append_text(_rich_bar(percent, bar_width, status))
        text.append(f" {percent:5.1f}% | ", style="bold #0fd139")
        text.append(
            f"{_format_bytes(completed)} / {_format_bytes(total) if total else '?'}",
            style="bold #8eeeff",
        )
        text.append(" | ", style="white")
        text.append(speed_label, style=speed_style)
        text.append(" | ", style="white")
        text.append("ETA ", style="#ffd04a")
        text.append(eta, style=eta_style)
        if include_elapsed:
            # Wall-clock operation time from one monotonic clock owned by the
            # view; frozen exactly at terminal state by close().
            elapsed_ref = self.finished_at if self.finished_at is not None else time.perf_counter()
            text.append(" | Elapsed ", style="white")
            text.append(format_eta(elapsed_ref - self.started_at), style="bold #d99145")
            if width >= 124:
                item_text = f" | {self.completed_items}/{self.total_items} {self.item_label}"
                if self.failed_items:
                    item_text += f", {self.failed_items} failed"
                text.append(item_text, style="yellow" if self.failed_items else "cyan")
        return text

    @staticmethod
    def _state_style(status: str) -> str:
        if status in {"complete", "downloaded", "resumed"}:
            return "bold green"
        if status in {"failed", "error"}:
            return "bold red"
        if status in {"queued", "skipped", "canceled"}:
            return "yellow"
        return "bold white"


def _format_bytes(size: int | float | None) -> str:
    value = float(size or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.2f} TB"


def _format_speed(speed: float | None) -> str:
    if speed is None:
        return "--"
    return f"{_format_bytes(speed)}/s"


def _shorten_middle(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    left = max(1, limit // 2 - 2)
    right = max(1, limit - left - 3)
    return text[:left] + "..." + text[-right:]


def _bar_parts(percent: float, width: int) -> tuple[int, int]:
    width = max(1, int(width))
    filled = int(max(0.0, min(100.0, percent)) / 100.0 * width)
    return filled, max(0, width - filled)


def _rich_bar(percent: float, width: int, status: str = "active") -> Text:
    filled, empty = _bar_parts(percent, width)
    text = Text()
    failed = status in {"failed", "error"}
    text.append("━" * filled, style="bold #ff4f6d" if failed else "bold #00bfb9")
    text.append("─" * empty, style="#5a1f2b" if failed else "#d60044")
    return text
