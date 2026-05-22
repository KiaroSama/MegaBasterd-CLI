"""Interactive prompt helpers using Rich."""

from __future__ import annotations

from getpass import getpass

from rich.prompt import Confirm, Prompt

from .theme import make_console

_console = make_console()


def ask(question: str, default: str | None = None) -> str:
    return Prompt.ask(question, default=default or "")


def ask_password(question: str = "Password") -> str:
    # Rich Prompt doesn't fully hide input on all terminals; use getpass for safety.
    return getpass(f"{question}: ")


def confirm(question: str, default: bool = True) -> bool:
    return Confirm.ask(question, default=default)


def print_panel(text: str, title: str = "", style: str = "cyan") -> None:
    from rich.panel import Panel

    _console.print(Panel(text, title=title, border_style=style))


def print_success(msg: str) -> None:
    _console.print(f"[mb.success]OK[/mb.success]  {msg}")


def print_error(msg: str) -> None:
    _console.print(f"[mb.error]ERR[/mb.error] {msg}")


def print_warn(msg: str) -> None:
    _console.print(f"[mb.warning]!![/mb.warning]  {msg}")


def print_info(msg: str) -> None:
    _console.print(f"[mb.info]i[/mb.info]   {msg}")
