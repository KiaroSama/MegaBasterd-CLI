"""Interactive prompt helpers using Rich."""

from __future__ import annotations

from getpass import getpass

from rich.prompt import Confirm, Prompt
from rich.text import Text

from .theme import literal, make_console, markup

_console = make_console()


def _line(prefix: str, msg: str | Text) -> Text:
    """Trusted `prefix` markup + untrusted `msg` rendered verbatim.

    Callers routinely build `msg` as an f-string around server-supplied text, so
    it is escaped by default; pass `markup(...)` to opt a message into styling.
    """
    return markup(prefix).append_text(literal(msg))


def ask(question: str, default: str | None = None) -> str:
    return Prompt.ask(question, default=default or "")


def ask_mfa_code() -> str:
    """The 2FA prompt every login path shares.

    It was written out identically in four command modules and once more as
    an inline lambda, so "change the wording" meant finding five places.
    """
    return ask("Enter 6-digit 2FA code").strip()


def ask_password(question: str = "Password") -> str:
    # Rich Prompt doesn't fully hide input on all terminals; use getpass for safety.
    return getpass(f"{question}: ")


def confirm(question: str, default: bool = True) -> bool:
    return Confirm.ask(question, default=default)


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
