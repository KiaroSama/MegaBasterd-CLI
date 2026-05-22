"""Shared Rich theme for MegaBasterd CLI output."""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

PALETTE = {
    "primary": "#4F8CFF",
    "secondary": "#8B5CF6",
    "accent": "#14B8A6",
    "success": "#22C55E",
    "warning": "#F59E0B",
    "error": "#EF4444",
    "info": "#38BDF8",
    "muted": "#94A3B8",
    "path": "#A3E635",
    "command": "#F472B6",
    "option": "#FACC15",
    "value": "#2DD4BF",
    "prompt": "#FB7185",
    "install": "#06B6D4",
    "python": "#60A5FA",
    "module": "#C084FC",
    "network": "#34D399",
    "dim": "#64748B",
    "header": "#F97316",
    "highlight": "#E879F9",
}

THEME = Theme(
    {
        "mb.primary": f"bold {PALETTE['primary']}",
        "mb.secondary": PALETTE["secondary"],
        "mb.accent": PALETTE["accent"],
        "mb.success": f"bold {PALETTE['success']}",
        "mb.warning": f"bold {PALETTE['warning']}",
        "mb.error": f"bold {PALETTE['error']}",
        "mb.info": PALETTE["info"],
        "mb.muted": PALETTE["muted"],
        "mb.path": PALETTE["path"],
        "mb.command": f"bold {PALETTE['command']}",
        "mb.option": PALETTE["option"],
        "mb.value": PALETTE["value"],
        "mb.prompt": f"bold {PALETTE['prompt']}",
        "mb.install": PALETTE["install"],
        "mb.python": PALETTE["python"],
        "mb.module": PALETTE["module"],
        "mb.network": PALETTE["network"],
        "mb.dim": PALETTE["dim"],
        "mb.header": f"bold {PALETTE['header']}",
        "mb.highlight": f"bold {PALETTE['highlight']}",
        "mb.table.header": f"bold {PALETTE['info']}",
        "mb.table.border": PALETTE["secondary"],
        "mb.progress": PALETTE["primary"],
        "mb.progress.done": PALETTE["success"],
        "mb.progress.pulse": PALETTE["highlight"],
    }
)


def make_console(**kwargs) -> Console:
    """Create a Console that uses the shared project theme."""
    return Console(theme=THEME, **kwargs)
