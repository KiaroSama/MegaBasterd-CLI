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


def run_post_transfer_command(command: str | None, path: Path) -> None:
    """Spawn `command path` after a successful transfer.

    The transferred path is appended as exactly one argv item. The command
    runs detached; its stdout/stderr are discarded. Errors are swallowed
    because hook failures must never break the transfer. Only the executable
    name is logged: configured hook arguments may carry secrets (tokens,
    passwords) and must not reach the log.
    """
    if not command:
        return
    try:
        argv = parse_hook_command(command) + [str(path)]
        log.info(
            "Running post-transfer command: %s (%d args) %s",
            argv[0] if argv else "?",
            max(0, len(argv) - 2),
            path,
        )
        subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("Post-transfer command failed: %s", exc)


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
