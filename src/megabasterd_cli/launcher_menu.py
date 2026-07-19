"""Interactive launcher menu, moved out of Run.ps1.

Run.ps1 keeps only what genuinely must be PowerShell (repo-root resolution,
interpreter/venv prerequisites, ``Start-Transcript`` and the transcript scrub).
The menu tree, the prompt flows and their validation, the argument construction
and the launcher-log redaction live here so they reuse the project's Rich theme
and the central ``utils.redaction`` sanitizer instead of duplicating them in
PowerShell regex.

Single module rather than a package: it is one cohesive responsibility (drive
the menu, build argv, dispatch) and well under the size where splitting helps.

Invoked as ``python -m megabasterd_cli.launcher_menu [cli args...]``. With
arguments it dispatches them straight to the CLI; with none it opens the menu.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from .cli import _redacted_argv
from .ui.prompts import ask_password
from .ui.theme import literal, make_console
from .utils.redaction import REDACTED, SECRET_FIELD_NAMES, redact_text, sanitize

console = make_console()

QUIT_TOKEN = "exit"

# `"api_key": "..."` inside a string that is NOT valid JSON (truncated, or
# embedded in a larger argument). Built from the central secret-field list so
# it cannot drift from it.
_JSON_FIELD = re.compile(
    r'("(?:{})"\s*:\s*)"[^"]*"?'.format("|".join(sorted(SECRET_FIELD_NAMES))),
    re.IGNORECASE,
)


class _Back(Exception):  # noqa: N818 - navigation signal, not an error
    """User asked to step back one prompt / leave the current menu."""


class _Quit(Exception):  # noqa: N818 - navigation signal, not an error
    """User asked to leave the launcher entirely."""


# --------------------------------------------------------------------------
# Paths and logging (the launcher log file is created by Run.ps1)
# --------------------------------------------------------------------------


def project_root() -> Path:
    root = os.environ.get("MEGABASTERD_PROJECT_ROOT")
    return Path(root) if root else Path(__file__).resolve().parents[2]


def log(level: str, message: str) -> None:
    """Append to the launcher log Run.ps1 opened. Never fatal."""
    path = os.environ.get("MEGABASTERD_LAUNCHER_LOG_FILE")
    if not path:
        return
    try:
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(f"{stamp} [{level}] {redact_text(message)}\n")
    except OSError:
        pass


# --------------------------------------------------------------------------
# Redaction for the launcher log
# --------------------------------------------------------------------------


def redact_args(args: Sequence[str]) -> list[str]:
    """Redact an argv for logging.

    Three passes, because secrets arrive in three shapes:
    1. ``_redacted_argv`` - by OPTION NAME (``--token x``, ``--token=x``) and
       MEGA links; shared with the CLI's own startup logging.
    2. JSON positionals - by VALUE, not by option name: ``config set
       elc_accounts {"host":{"api_key":"..."}}`` carries the secret in a
       positional. Parsed and run through the central recursive ``sanitize``,
       which also covers nesting and every field in ``SECRET_FIELD_NAMES``.
    3. ``redact_text`` plus ``_JSON_FIELD`` for the remaining free-text shapes,
       including JSON-ish payloads too malformed to parse.
    """
    out: list[str] = []
    for arg in _redacted_argv(list(args)):
        stripped = arg.strip()
        if stripped[:1] in ("{", "["):
            try:
                out.append(json.dumps(sanitize(json.loads(stripped)), separators=(",", ":")))
                continue
            except (ValueError, TypeError):
                pass  # not JSON after all; fall through to the text passes
        out.append(_JSON_FIELD.sub(rf'\1"{REDACTED}"', redact_text(arg)))
    return out


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _section(title: str) -> None:
    console.print()
    console.print(literal(f"{title}:"), style="mb.header")


def _option_line(key: str, label: str) -> None:
    suffix = " [1]" if key == "1" else ""
    console.print(literal(f"  {key}. {label}{suffix}"), style="mb.value")


def _note(message: str, style: str = "mb.info") -> None:
    console.print(literal(message), style=style)
    log("INFO", message)


def _nav_hint(allow_back: bool, back_token: str = "0") -> str:
    return f" {{back={back_token}, quit=exit}}: " if allow_back else " {quit=exit}: "


def _display_path(value: str) -> str:
    """Shorten a path for display only (never changes the stored value)."""
    try:
        parent = str(project_root().parent).rstrip("\\/")
        full = str(Path(value).resolve())
        if full.lower().startswith(parent.lower() + os.sep):
            return "." + os.sep + full[len(parent) + 1 :]
    except OSError:
        pass
    return value


# --------------------------------------------------------------------------
# Input
# --------------------------------------------------------------------------


def _classify(answer: str, allow_back: bool, back_token: str) -> None:
    """Raise for the navigation tokens; return for ordinary input."""
    trimmed = answer.strip()
    if trimmed.lower() == QUIT_TOKEN:
        log("INFO", "User requested launcher exit.")
        raise _Quit()
    # `back` always navigates; the numeric token is per-prompt so that a speed
    # limit of `0` stays a usable value rather than a back command.
    if allow_back and (trimmed == back_token or trimmed.lower() == "back"):
        log("INFO", "User requested launcher back navigation.")
        raise _Back()


def _read_line(prompt: str) -> str:
    console.print()
    try:
        return input(prompt)
    except EOFError as exc:
        raise _Quit() from exc


def ask_text(
    message: str,
    default: str = "",
    allow_back: bool = True,
    display_default: str | None = None,
    back_token: str = "0",
    numeric: bool = False,
) -> str:
    """Prompt for a line, applying the default and the navigation tokens."""
    shown = display_default if display_default else default
    label = f"{message} [{shown}]" if default else message
    while True:
        answer = _read_line(label + _nav_hint(allow_back, back_token))
        log("PROMPT", f"{label}{_nav_hint(allow_back, back_token)}")
        _classify(answer, allow_back, back_token)
        value = answer.strip() or default
        if numeric and not _is_valid_number(value):
            _note(f"Enter a whole number >= 0 (got: {value!r}).", "mb.warning")
            continue
        return value


def _is_valid_number(value: str) -> bool:
    if not value:
        return True  # blank keeps the default / omits the option
    try:
        return int(value) >= 0
    except ValueError:
        return False


def ask_secret(message: str, allow_back: bool = True) -> str:
    console.print()
    value = ask_password(f"{message} [blank to skip]{_nav_hint(allow_back).rstrip(': ')}")
    log("PROMPT", f"{message} (secret input)")
    _classify(value, allow_back, "0")
    return value


def ask_yes_no(message: str, default: bool = True, allow_back: bool = True) -> bool:
    label = f"{message} (y/n) [{'Y' if default else 'N'}]"
    answer = _read_line(label + _nav_hint(allow_back))
    log("PROMPT", label)
    _classify(answer, allow_back, "0")
    trimmed = answer.strip().lower()
    if not trimmed:
        return default
    return trimmed in ("y", "yes")


def ask_choice(count: int, allow_back: bool = True) -> str:
    """Read a menu selection. Blank selects 1; 'exit'/'0' navigate."""
    answer = _read_line("Selection [1]" + _nav_hint(allow_back))
    log("PROMPT", f"Selection [1]{_nav_hint(allow_back)}")
    trimmed = answer.strip().lower()
    if trimmed == QUIT_TOKEN:
        log("INFO", "User requested launcher exit.")
        raise _Quit()
    if not trimmed:
        return "1"
    if allow_back and trimmed == "0":
        raise _Back()
    if not trimmed.isdigit() or not 1 <= int(trimmed) <= count:
        _note("Invalid selection.", "mb.warning")
        return ""
    return trimmed


def split_args(text: str) -> list[str]:
    """Split a free-form extra-options string into argv."""
    if not text or not text.strip():
        return []
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------


def dispatch(args: Sequence[str], return_to_menu: bool = True) -> int:
    args = [str(a) for a in args]
    if not args:
        return 0
    log("INFO", "Dispatching CLI args: " + " ".join(redact_args(args)))
    code = subprocess.call([sys.executable, "-m", "megabasterd_cli", *args])
    log("INFO", f"CLI exit code: {code}")
    if return_to_menu:
        if code == 0:
            _note("Command completed successfully.", "mb.success")
        else:
            _note(
                f"Command failed with exit code {code}. Check the Logs directory for details.",
                "mb.error",
            )
        ask_text("Press Enter to return to the menu", allow_back=False)
    return int(code)


# --------------------------------------------------------------------------
# Wizards (declarative steps -> argv)
# --------------------------------------------------------------------------


@dataclass
class Step:
    key: str
    label: str
    kind: str = "text"  # text | secret | yesno
    default: object = ""
    option: str | None = None  # CLI option this value feeds, if any
    required: bool = False  # blank answer abandons the wizard
    numeric: bool = False
    raw: bool = False  # free-form extras appended verbatim
    path: bool = False  # shorten the shown default
    back_token: str = "0"


def _ask_step(step: Step, current: object) -> object:
    if step.kind == "secret":
        return ask_secret(step.label)
    if step.kind == "yesno":
        return ask_yes_no(step.label, bool(current))
    return ask_text(
        step.label,
        str(current or ""),
        display_default=_display_path(str(current)) if step.path and current else None,
        numeric=step.numeric,
        back_token=step.back_token,
    )


def run_wizard(title: str, steps: Sequence[Step]) -> dict[str, object] | None:
    """Drive the steps with back-one-step navigation. None = abandoned."""
    if title:
        _section(title)
    values: dict[str, object] = {s.key: s.default for s in steps}
    index = 0
    while index < len(steps):
        step = steps[index]
        try:
            values[step.key] = _ask_step(step, values[step.key])
        except _Back:
            if index == 0:
                return None
            index -= 1
            continue
        if step.required and not str(values[step.key]).strip():
            return None
        index += 1
    return values


def build_args(
    prefix: Sequence[str], steps: Sequence[Step], values: dict[str, object]
) -> list[str]:
    args = list(prefix)
    for step in steps:
        value = values.get(step.key)
        if step.raw:
            args += split_args(str(value or ""))
        elif not step.option:
            continue
        elif step.kind == "yesno":
            if value:
                args.append(step.option)
        elif str(value or "").strip():
            args += [step.option, str(value)]
    return args


LINK_MARKERS = ("mega.nz/", "mega.co.nz/", "mc://", "mega://")


def download_wizard() -> None:
    steps = [
        Step("source", "MEGA link(s), or a text/DLC file path", required=True),
        Step(
            "output",
            "Output directory",
            default=str(project_root() / "Output"),
            option="-o",
            path=True,
        ),
        Step("workers", "Workers per file", default="8", option="-w", numeric=True),
        Step(
            "parallel",
            "Parallel files (simultaneous files)",
            default="6",
            option="-P",
            numeric=True,
        ),
        Step(
            "limit",
            "Speed limit KB/s (0 = unlimited)",
            default="0",
            option="-l",
            numeric=True,
            back_token="back",
        ),
        Step("password", "Link password", kind="secret", option="-p"),
        Step("rename", "Rename single file to [blank = original name]", option="--rename"),
        Step("proxy", "Proxy URL [blank = none/config]", option="--proxy"),
        Step(
            "no_verify",
            "Skip final integrity check? (not recommended)",
            kind="yesno",
            default=False,
            option="--no-verify",
        ),
    ]
    values = run_wizard("Download", steps)
    if values is None:
        return
    source = str(values["source"])
    head: list[str] = ["download"]
    if Path(source).exists() and not any(m in source for m in LINK_MARKERS):
        head += ["-i", source]
    else:
        head += split_args(source)
    dispatch(build_args(head, steps, values))


def info_wizard() -> None:
    steps = [
        Step("url", "MEGA link", required=True),
        Step("password", "Link password", kind="secret", option="--password"),
    ]
    values = run_wizard("Link Info", steps)
    if values is None:
        return
    dispatch(build_args(["info", str(values["url"])], steps, values))


def upload_wizard() -> None:
    steps = [
        Step("paths", "Local file/folder path(s)", required=True),
        Step("account", "Account email/label [blank = default]", option="-a"),
        Step(
            "target", "Remote target folder handle/path [blank = account root]", option="--target"
        ),
        Step("workers", "Workers per file", default="8", option="-w", numeric=True),
        Step(
            "parallel",
            "Parallel files (simultaneous files)",
            default="6",
            option="-P",
            numeric=True,
        ),
        Step(
            "limit",
            "Upload speed limit KB/s (0 = unlimited)",
            default="0",
            option="-l",
            numeric=True,
            back_token="back",
        ),
        Step(
            "keep", "Keep folder structure?", kind="yesno", default=True, option="--keep-structure"
        ),
        Step(
            "auto",
            "Auto-pick account by free space?",
            kind="yesno",
            default=False,
            option="--auto-account",
        ),
        Step(
            "share",
            "Create public links after upload?",
            kind="yesno",
            default=False,
            option="--share",
        ),
        Step("vault", "Vault passphrase", kind="secret", option="--vault-passphrase"),
        Step("extra", "Extra options for upload [blank for none]", raw=True),
    ]
    values = run_wizard("Upload", steps)
    if values is None:
        return
    head = ["upload", *split_args(str(values["paths"]))]
    dispatch(build_args(head, steps, values))


def account_add_wizard() -> None:
    steps = [
        Step("email", "Email", required=True),
        Step("label", "Label [blank = none]", option="--label"),
        Step("default", "Make default account?", kind="yesno", default=True, option="--default"),
        Step("verify", "Verify login now?", kind="yesno", default=True),
        Step("vault", "Vault passphrase", kind="secret", option="--vault-passphrase"),
    ]
    values = run_wizard("", steps)
    if values is None:
        return
    args = build_args(["account", "add", str(values["email"])], steps, values)
    if not values["verify"]:
        args.append("--no-verify")
    dispatch(args)


def elc_credentials_wizard() -> None:
    steps = [
        Step("host", "ELC host", required=True),
        Step("user", "ELC user", required=True),
        Step("api_key", "ELC API key", kind="secret"),
    ]
    values = run_wizard("", steps)
    if values is None or not str(values["api_key"]).strip():
        return
    payload = json.dumps(
        {str(values["host"]): {"user": str(values["user"]), "api_key": str(values["api_key"])}},
        separators=(",", ":"),
    )
    dispatch(["config", "set", "elc_accounts", payload])


def generic_wizard(command: str, prompt: str) -> None:
    _section(command)
    try:
        raw = ask_text(prompt)
    except _Back:
        return
    if not raw.strip():
        _note("No arguments entered.", "mb.warning")
        ask_text("Press Enter to return to the menu", allow_back=False)
        return
    dispatch([command, *split_args(raw)])


def config_set_wizard(key: str, prompt: str, default: str = "", back_token: str = "0") -> None:
    try:
        value = ask_text(prompt, default, back_token=back_token)
    except _Back:
        return
    if value.strip():
        dispatch(["config", "set", key, value])


def advanced_wizard() -> None:
    try:
        raw = ask_text("Enter CLI arguments")
    except _Back:
        return
    if raw.strip():
        dispatch(split_args(raw))


# --------------------------------------------------------------------------
# Menu tree
# --------------------------------------------------------------------------

Action = Callable[[], None]


def cmd(*args: str) -> Action:
    def run() -> None:
        dispatch(list(args))

    return run


def generic(command: str, prompt: str) -> Action:
    return lambda: generic_wizard(command, prompt)


@dataclass
class Menu:
    title: str
    entries: list[tuple[str, Action]] = field(default_factory=list)
    subtitle: str | None = None


ACCOUNT_MENU = Menu(
    "Account and Cloud",
    [
        ("Add/login account", account_add_wizard),
        ("List stored accounts", cmd("account", "list")),
        ("Set default account", generic("account", "Enter: default <email-or-label>")),
        ("Show account quota", generic("account", "Enter: info [email-or-label] [options]")),
        (
            "List cloud files",
            generic("ls", "Enter remote path/options [blank path is root; type . for root]"),
        ),
        ("Search cloud", generic("search", "Enter search query/options")),
        ("Create remote folder", generic("mkdir", "Enter remote folder path/options")),
        ("Rename remote node", generic("rename", "Enter node handle/path and new name/options")),
        ("Move remote node", generic("mv", "Enter source node and destination/options")),
        ("Remove remote node", generic("rm", "Enter node handle/path/options")),
        ("Trash operations", generic("trash", "Enter list or empty [options]")),
        ("Share remote node", generic("share", "Enter node handle/path/options")),
        (
            "Import public folder to account",
            generic("import", "Enter public folder link and destination/options"),
        ),
    ],
)

QUEUE_MENU = Menu(
    "Queue and Proxy",
    [
        ("Queue: add download", generic("queue", "Enter: add-download <url> [options]")),
        ("Queue: add upload", generic("queue", "Enter: add-upload <path> [options]")),
        ("Queue: list", cmd("queue", "list")),
        ("Queue: run", generic("queue", "Enter: run [options]")),
        ("Queue: remove", generic("queue", "Enter: remove <id>")),
        ("Queue: clear completed/canceled", cmd("queue", "clear")),
        ("Proxy: list", cmd("proxy", "list")),
        ("Proxy: add", generic("proxy", "Enter: add <proxy-url> [more-url...]")),
        ("Proxy: remove", generic("proxy", "Enter: remove <proxy-url>")),
        ("Proxy: import from file", generic("proxy", "Enter: import <file-path>")),
        ("Proxy: fetch public list", generic("proxy", "Enter: fetch [options]")),
        ("Proxy: clear", cmd("proxy", "clear")),
        (
            "Watch clipboard and queue links",
            generic("watch", "Enter watch options [blank is not accepted]"),
        ),
    ],
)

TOOLS_MENU = Menu(
    "Tools",
    [
        ("Split file", generic("split", "Enter <source> <part-size-mb> [options]")),
        ("Merge parts", generic("merge", "Enter <any-part-file> [options]")),
        (
            "Encrypt local file",
            generic("crypter", "Enter: encrypt <source> <destination> [options]"),
        ),
        (
            "Decrypt local file",
            generic("crypter", "Enter: decrypt <source> <destination> [options]"),
        ),
        ("Resolve MegaCrypter link", generic("crypter", "Enter: resolve <mc-url> [options]")),
        (
            "Resolve ELC container",
            generic("crypter", "Enter: elc-resolve <mega://elc...> [options]"),
        ),
        ("Resolve DLC container", generic("crypter", "Enter: dlc-resolve <path>")),
        ("Create thumbnail", generic("thumbnail", "Enter <source-image> <destination-jpg>")),
        ("Stream MEGA file", generic("stream", "Enter <mega-link> [options]")),
    ],
)

SETTINGS_MENU = Menu(
    "Settings",
    [
        ("Show current configuration", cmd("config", "show")),
        (
            "Set default download folder",
            lambda: config_set_wizard(
                "download_path", "Default download folder", str(project_root() / "Output")
            ),
        ),
        ("Set download workers", lambda: config_set_wizard("max_workers", "Download workers", "8")),
        (
            "Set speed limit",
            lambda: config_set_wizard(
                "speed_limit_kbps", "Speed limit KB/s (0 = unlimited)", "0", back_token="back"
            ),
        ),
        ("Set ELC API credentials", elc_credentials_wizard),
        ("Add/login MEGA account", account_add_wizard),
        ("List accounts", cmd("account", "list")),
        ("Set default account", generic("account", "Enter: default <email-or-label>")),
        ("Show config path", cmd("config", "path")),
        ("Reset config", cmd("config", "reset")),
    ],
)


def _main_menu() -> Menu:
    return Menu(
        "MegaBasterd-CLI Main menu",
        [
            ("Download MEGA link/file", download_wizard),
            ("Show link info", info_wizard),
            ("Upload file/folder", upload_wizard),
            ("Account and cloud operations", lambda: run_menu(ACCOUNT_MENU)),
            ("Queue and proxy", lambda: run_menu(QUEUE_MENU)),
            ("Tools", lambda: run_menu(TOOLS_MENU)),
            ("Settings", lambda: run_menu(SETTINGS_MENU)),
            ("Advanced CLI command", advanced_wizard),
        ],
    )


def run_menu(menu: Menu, allow_back: bool = True) -> None:
    while True:
        _section(menu.title)
        if menu.title == "Settings":
            console.print(
                literal(f"User data: {os.environ.get('MEGABASTERD_USER_DIR', '')}"), style="mb.path"
            )
        for number, (label, _action) in enumerate(menu.entries, start=1):
            _option_line(str(number), label)
        try:
            choice = ask_choice(len(menu.entries), allow_back)
        except _Back:
            return
        if not choice:
            continue
        try:
            menu.entries[int(choice) - 1][1]()
        except _Back:
            continue


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if args:
            return dispatch(args, return_to_menu=False)
        log("INFO", "No command was supplied; opening launcher menu.")
        run_menu(_main_menu(), allow_back=False)
    except (_Quit, _Back):
        pass
    except KeyboardInterrupt:
        log("INFO", "Launcher interrupted.")
        return 130
    log("INFO", "User exited launcher menu.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
