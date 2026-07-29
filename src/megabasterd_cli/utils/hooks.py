"""Post-transfer hooks: run a shell command, append to an upload log."""

from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import shlex
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)


def parse_hook_command(command: str) -> list[str]:
    """Split a configured hook command into argv, per-platform.

    Windows paths need non-POSIX splitting (backslashes are not escapes);
    POSIX systems need real POSIX quoting rules. Never uses shell=True.
    """
    return shlex.split(command, posix=(os.name != "nt"))


def _spawn_hook(command: str, appended: list[str], label: str) -> None:
    """Spawn `command` with `appended` added as individual argv items.

    The one place every hook is started, so the two properties that matter
    cannot drift apart: never `shell=True`, and only the executable name plus
    the NUMBER of configured arguments is logged - a configured hook argument
    may carry a secret (token, password) and must not reach the log. The
    appended items are ours, not the user's, so they are safe to log.

    The command runs detached; its stdout/stderr are discarded. Errors are
    swallowed because a hook failure must never break the transfer.
    """
    try:
        argv = parse_hook_command(command) + appended
        log.info(
            "Running %s: %s (%d args) %s",
            label,
            argv[0] if argv else "?",
            max(0, len(argv) - 1 - len(appended)),
            " ".join(appended),
        )
        subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("%s failed: %s", label.capitalize(), exc)


def run_post_transfer_command(command: str | None, path: Path) -> None:
    """Spawn `command path` after a successful transfer.

    The transferred path is appended as exactly one argv item.
    """
    if not command:
        return
    _spawn_hook(command, [str(path)], "post-transfer command")


def run_all_finished_command(
    command: str | None, *, kind: str, succeeded: int, failed: int
) -> None:
    """Spawn `command <kind> <succeeded> <failed>` ONCE, after a whole batch.

    The per-file `run_command` hook cannot express "the batch is done": the
    last file's hook has no way to know it was the last. This is the hook for
    "shut the machine down", "play a sound", "start the next stage".

    `kind` is "download", "upload" or "queue" so one script can serve all
    three. Nothing secret is passed. An EMPTY batch (nothing attempted) is
    filtered here rather than at each call site, so no caller can forget it.

    Failure handling matches the per-file hook: fire-and-forget, and a hook
    that cannot be started is logged, never fatal.
    """
    if not command or succeeded + failed <= 0:
        return
    _spawn_hook(command, [kind, str(succeeded), str(failed)], "all-finished command")


def append_upload_log(
    log_path: str | None,
    *,
    local_path: Path,
    file_handle: str,
    size: int,
    elapsed_seconds: float,
    public_link: str | None = None,
    account: str | None = None,
) -> None:
    """Append a single JSON line summarising an upload to `log_path`."""
    if not log_path:
        return
    record = {
        "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "path": str(local_path),
        "name": local_path.name,
        "handle": file_handle,
        "size": size,
        "elapsed_seconds": round(elapsed_seconds, 2),
        "account": account,
        "public_link": public_link,
    }
    p = Path(log_path)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError as exc:
        log.warning("Could not write upload log %s: %s", log_path, exc)
