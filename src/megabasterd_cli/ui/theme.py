"""Shared Rich theme for MegaBasterd CLI output."""

from __future__ import annotations

import re
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

PALETTE = {
    "secondary": "#8B5CF6",
    "success": "#22C55E",
    "warning": "#F59E0B",
    "error": "#EF4444",
    "info": "#38BDF8",
    "muted": "#94A3B8",
    "path": "#A3E635",
    "option": "#FACC15",
    "value": "#2DD4BF",
    "prompt": "#FB7185",
    "command": "#F472B6",
    "dim": "#64748B",
    # Read by the restored ui.progress compatibility surface.
    "highlight": "#E879F9",
    "primary": "#4F8CFF",
    # Launcher menu chrome, matched to the sibling FFmWiz launcher so the two
    # read as one family. These are that tool's literal ANSI colours, not
    # approximations: xterm 117 for the option keys and headings, ANSI bright
    # green for a default you can accept by pressing Enter, and xterm 166 / 32
    # for the back / exit hints - one hue per navigation meaning.
    "menu_key": "color(117)",
    "menu_default": "bright_green",
    "hint_back": "color(166)",
    "hint_exit": "color(32)",
    "hint_folder": "#B48CFF",
    "hint_other": "bright_white",
}

THEME = Theme(
    {
        "mb.success": f"bold {PALETTE['success']}",
        "mb.warning": f"bold {PALETTE['warning']}",
        "mb.error": f"bold {PALETTE['error']}",
        "mb.info": PALETTE["info"],
        "mb.muted": PALETTE["muted"],
        "mb.path": PALETTE["path"],
        "mb.option": PALETTE["option"],
        "mb.value": PALETTE["value"],
        "mb.prompt": f"bold {PALETTE['prompt']}",
        "mb.dim": PALETTE["dim"],
        # Menu chrome. Each part of a row is a different kind of thing - an
        # index you type, a label you read, a default you can just accept - so
        # each gets its own colour instead of one flat style for the row.
        #
        # The label is deliberately UNSTYLED: colouring it too made every row a
        # second accent competing with the key, which is what stopped the list
        # reading as a list. Brackets are unstyled for the same reason - in
        # FFmWiz the `[` `]` and `{` `}` are punctuation, and only what is
        # inside them carries colour.
        "mb.title": f"bold {PALETTE['menu_key']}",
        "mb.menu.key": PALETTE["menu_key"],
        "mb.menu.label": "none",
        "mb.menu.default": PALETTE["menu_default"],
        "mb.prompt.label": "bold",
        "mb.prompt.punct": "none",
        "mb.prompt.back": PALETTE["hint_back"],
        "mb.prompt.exit": PALETTE["hint_exit"],
        "mb.prompt.folder": PALETTE["hint_folder"],
        "mb.prompt.other": PALETTE["hint_other"],
        # Consumed by build_progress / ProgressReporter, kept for the 1.x
        # compatibility surface.
        "mb.command": f"bold {PALETTE['command']}",
        "mb.highlight": f"bold {PALETTE['highlight']}",
        "mb.progress": PALETTE["primary"],
        "mb.progress.done": PALETTE["success"],
        "mb.progress.pulse": PALETTE["highlight"],
        "mb.table.header": f"bold {PALETTE['info']}",
        "mb.table.border": PALETTE["secondary"],
    }
)


def make_console(**kwargs) -> Console:
    """Create a Console that uses the shared project theme."""
    return Console(theme=THEME, **kwargs)


# ---------------------------------------------------------------------------
# Trusted / untrusted boundary
#
# Rich parses plain `str` as markup, so any remote-controlled value (a MEGA
# filename, a MegaCrypter server response, a server-supplied error string) could
# choose its own styling, or abort the whole render with `MarkupError` on an
# unbalanced tag. The rule enforced here: a plain `str` is UNTRUSTED and is shown
# literally; app-authored styling must be opted in via `markup()`.
# ---------------------------------------------------------------------------


def markup(text: str) -> Text:
    """Mark app-authored text as trusted Rich markup (`[mb.dim]...[/mb.dim]`)."""
    return Text.from_markup(text)


def literal(text: object) -> Text:
    """Wrap an untrusted value so Rich renders it verbatim."""
    return text if isinstance(text, Text) else Text(str(text))


class SafeTable(Table):
    """`rich.table.Table` that treats plain `str` cells as untrusted literal text.

    Use `markup("[mb.success]Y[/mb.success]")` for deliberate in-cell styling;
    column-level `style=` is unaffected and remains the normal way to colour a
    column.
    """

    def add_row(self, *renderables: Any, **kwargs: Any) -> None:
        super().add_row(
            *(Text(cell) if type(cell) is str else cell for cell in renderables),
            **kwargs,
        )


# ---------------------------------------------------------------------------
# Prompt styling
#
# Lives here, not in the launcher, because BOTH sides render prompts and they
# appear on one screen: the launcher shells out to the CLI, so a `[default]`
# styled in one and plain in the other is visible in a single session. One
# implementation means a new prompt is coloured correctly without its author
# having to remember anything.
# ---------------------------------------------------------------------------

_PROMPT_PART = re.compile(r"(\[[^\]]*\]|\{[^}]*\})")

_HINT_STYLES = (
    ("back", "mb.prompt.back"),
    ("exit", "mb.prompt.exit"),
    ("folder", "mb.prompt.folder"),
)


def _append_hints(styled: Text, group: str) -> None:
    """Colour each `{...}` navigation token by what it does, not by position.

    `back=0` and `quit=exit` used to share one style, so the two hints that
    behave most differently looked identical. One hue per meaning makes "go
    back" and "leave entirely" distinguishable at a glance.
    """
    styled.append("{", style="mb.prompt.punct")
    for index, token in enumerate(group[1:-1].split(", ")):
        if index:
            styled.append(", ", style="mb.prompt.punct")
        lowered = token.lower()
        style = next((s for word, s in _HINT_STYLES if word in lowered), "mb.prompt.other")
        styled.append(token, style=style)
    styled.append("}", style="mb.prompt.punct")


def styled_prompt(prompt: str) -> Text:
    """Colour a prompt's bracketed default and braced hints separately.

    Every prompt in the project has the shape `label [default] {hints}: `, so
    one pass over that shape keeps them all consistent.
    """
    styled = Text()
    for part in _PROMPT_PART.split(prompt):
        if not part:
            continue
        if part.startswith("{"):
            _append_hints(styled, part)
        elif part.startswith("["):
            # Only the VALUE is coloured; the brackets are punctuation and stay
            # plain, exactly as `{`/`}`/`,` already do above. Colouring the
            # whole token made the delimiters compete with the one character
            # that carries the information.
            styled.append("[", style="mb.prompt.punct")
            styled.append(part[1:-1], style="mb.menu.default")
            styled.append("]", style="mb.prompt.punct")
        else:
            styled.append(part, style="mb.prompt.label")
    return styled
