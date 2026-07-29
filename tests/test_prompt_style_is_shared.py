"""The launcher and the CLI must render a prompt identically.

The launcher shells out to the CLI, so both appear in one session: a `[default]`
coloured in one and plain in the other is visible on screen, which is exactly
what happened - `[blank to skip]` arrived uncoloured next to a green `[Y]`
because `ask_password` treated the whole line as one label while the launcher
split and styled it.

They now share `ui.theme.styled_prompt`. These tests pin that: one styler, and
the bracketed default really is styled apart from the label.
"""

from __future__ import annotations

from rich.console import Console

from megabasterd_cli import launcher_menu as lm
from megabasterd_cli.ui import prompts
from megabasterd_cli.ui.theme import THEME, styled_prompt


def _render(text) -> str:
    console = Console(
        theme=THEME,
        force_terminal=True,
        color_system="truecolor",
        legacy_windows=False,
        no_color=False,
        width=100,
    )
    with console.capture() as captured:
        console.print(text, end="")
    return captured.get()


def test_the_launcher_uses_the_shared_styler_not_a_copy():
    assert lm._styled_prompt is styled_prompt


def test_the_cli_prompt_uses_the_shared_styler():
    """`_prompt_text` must route through it, or the two drift again."""
    assert _render(prompts._prompt_text("Question", "[Y]")) == _render(
        styled_prompt("Question [Y]: ")
    )


def test_a_bracketed_default_is_styled_apart_from_the_label():
    """The concrete regression: `[blank to skip]` rendered flat."""
    out = _render(styled_prompt("Vault passphrase [blank to skip] {back=0, quit=exit}: "))
    assert "\x1b[" in out.split("[blank to skip]")[0], "the default carries no style of its own"
    # The two navigation hints stay distinguishable from each other.
    assert out.count("\x1b[38;5;") >= 2


def test_the_password_prompt_is_styled_like_every_other_prompt():
    assert _render(prompts._prompt_text("Password for user@example.com")) == _render(
        styled_prompt("Password for user@example.com: ")
    )
