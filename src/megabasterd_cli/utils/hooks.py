"""Post-transfer hooks: run a shell command, append to an upload log."""

from __future__ import annotations

import json
import logging
import shlex
import subprocess
import datetime as _dt
from pathlib import Path

log = logging.getLogger(__name__)


def run_post_transfer_command(command: str | None, path: Path) -> None:
    """Spawn `command path` after a successful transfer.

    The command runs detached; its stdout/stderr go to the log. Errors are
    swallowed because hook failures must never break the transfer.
    """
    if not command:
        return
    try:
        argv = shlex.split(command, posix=False) + [str(path)]
        log.info("Running post-transfer command: %s", argv)
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
        "ts": _dt.datetime.utcnow().isoformat() + "Z",
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
