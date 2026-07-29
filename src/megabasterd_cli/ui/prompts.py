"""Interactive prompt helpers using Rich."""

from __future__ import annotations

from getpass import getpass

from rich.text import Text

from .theme import literal, make_console, markup, styled_prompt

_console = make_console()


def _line(prefix: str, msg: str | Text) -> Text:
    """Trusted `prefix` markup + untrusted `msg` rendered verbatim.

    Callers routinely build `msg` as an f-string around server-supplied text, so
    it is escaped by default; pass `markup(...)` to opt a message into styling.
    """
    return markup(prefix).append_text(literal(msg))


def _prompt_text(question: str, suffix: str = "") -> Text:
    """One prompt shape for the whole CLI: `label [default] {hints}: `.

    Rendered by the SAME styler the launcher uses (`ui.theme.styled_prompt`),
    because the launcher shells out to the CLI and the two alternate on one
    screen: anything styled here but not there - or the reverse - is visible in
    a single session. Left to Rich's defaults they disagreed twice over:
    `Confirm.ask` writes `[y/n] (n)`, inverting the launcher's `(y/n) [Y]`, and
    `getpass` emits no colour at all. Passing the whole line through one styler
    also means `[blank to skip]` and `{back=0, quit=exit}` are coloured for
    callers that build them, instead of arriving as one flat label.
    """
    line = f"{question} {suffix}: " if suffix else f"{question}: "
    return styled_prompt(line)


def _render_prompt(question: str, suffix: str = "") -> None:
    _console.print(_prompt_text(question, suffix), end="")


def ask(question: str, default: str | None = None) -> str:
    if default:
        _render_prompt(question, f"[{default}]")
    else:
        _render_prompt(question)
    try:
        answer = input("")
    except EOFError:
        return default or ""
    return answer.strip() or (default or "")


def ask_mfa_code() -> str:
    """The 2FA prompt every login path shares.

    It was written out identically in four command modules and once more as
    an inline lambda, so "change the wording" meant finding five places.
    """
    return ask("Enter 6-digit 2FA code").strip()


def ask_password(question: str = "Password") -> str:
    # The label is printed styled; getpass gets an empty prompt so it only has
    # to suppress the echo. Rich's Prompt cannot hide input on every terminal,
    # which is why the read itself stays with getpass.
    _render_prompt(question)
    return getpass("")


def confirm(question: str, default: bool = True) -> bool:
    """`question (y/n) [Y]: ` - the launcher's shape, not Rich's `[y/n] (n)`."""
    _render_prompt(f"{question} (y/n)", f"[{'Y' if default else 'N'}]")
    try:
        answer = input("")
    except EOFError:
        return default
    trimmed = answer.strip().lower()
    if not trimmed:
        return default
    return trimmed in ("y", "yes")


def print_success(msg: str | Text) -> None:
    _console.print(_line("[mb.success]OK[/mb.success]  ", msg))


def print_error(msg: str | Text) -> None:
    _console.print(_line("[mb.error]ERR[/mb.error] ", msg))


def print_warn(msg: str | Text) -> None:
    _console.print(_line("[mb.warning]!![/mb.warning]  ", msg))


def print_info(msg: str | Text) -> None:
    _console.print(_line("[mb.info]i[/mb.info]   ", msg))


def print_panel(text: str | Text, title: str = "", style: str = "cyan") -> None:
    """Compatibility surface retained for the 1.x series."""
    from rich.panel import Panel

    _console.print(Panel(literal(text), title=title, border_style=style))
