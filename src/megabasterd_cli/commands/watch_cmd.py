"""`mb watch` — clipboard spy that auto-queues MEGA links."""

from __future__ import annotations

import logging
import time
from pathlib import Path

import click

from ..config import data_dir
from ..core.links import is_mega_url
from ..queue.manager import JobStatus, JobType, QueueItem, QueueManager
from ..ui.prompts import print_info, print_success

log = logging.getLogger(__name__)


def _read_clipboard() -> str:
    """Read clipboard text, falling back gracefully across OSes."""
    # Try pyperclip first
    try:
        import pyperclip  # type: ignore

        return pyperclip.paste() or ""
    except ImportError:
        pass

    import platform
    import subprocess

    system = platform.system()
    try:
        if system == "Windows":
            # PowerShell Get-Clipboard works everywhere modern Windows runs.
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", "Get-Clipboard"],
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            return out.decode("utf-8", errors="replace").strip()
        if system == "Darwin":
            out = subprocess.check_output(["pbpaste"], timeout=5)
            return out.decode("utf-8", errors="replace")
        # Linux: try wl-paste then xclip
        for cmd in (["wl-paste", "-n"], ["xclip", "-selection", "clipboard", "-o"]):
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=5)
                return out.decode("utf-8", errors="replace")
            except (FileNotFoundError, subprocess.CalledProcessError):
                continue
    except Exception as exc:  # noqa: BLE001
        log.debug("Clipboard read failed: %s", exc)
    return ""


@click.command("watch", short_help="Watch the clipboard and queue any MEGA links copied.")
@click.option(
    "--interval",
    type=float,
    default=1.5,
    show_default=True,
    help="Polling interval in seconds.",
)
@click.option(
    "-o",
    "--output",
    "output_dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Output directory for queued downloads.",
)
@click.option(
    "--run",
    is_flag=True,
    help="Also run the queue continuously instead of just adding items.",
)
@click.option(
    "--vault-passphrase",
    default=None,
    help="Vault passphrase for queued uploads when used with --run.",
)
@click.option("--mfa-code", default=None, help="2FA code for queued uploads when used with --run.")
@click.pass_context
def watch_cmd(
    ctx: click.Context,
    interval: float,
    output_dir: Path | None,
    run: bool,
    vault_passphrase: str | None,
    mfa_code: str | None,
) -> None:
    """Continuously watch the system clipboard. When a MEGA URL appears, it is
    automatically added to the persistent download queue. Press Ctrl+C to stop.
    """
    cfg = ctx.obj["config"]
    q = QueueManager(data_dir() / "queue.json")
    out = str(output_dir) if output_dir else cfg.download_path

    print_info("Watching clipboard for MEGA links... (Ctrl+C to stop)")
    last_value = _read_clipboard()
    try:
        while True:
            time.sleep(interval)
            current = _read_clipboard()
            if not current or current == last_value:
                continue
            last_value = current
            # Look at every line in case multiple URLs were copied together
            for raw in current.splitlines():
                line = raw.strip()
                if not line or not is_mega_url(line):
                    continue
                # Avoid queuing the same URL twice in a row
                if any(i.source == line and i.status == JobStatus.PENDING.value for i in q.items):
                    continue
                item = QueueItem(
                    id=QueueItem.new_id(),
                    type=JobType.DOWNLOAD.value,
                    source=line,
                    destination=out,
                )
                q.add(item)
                print_success(f"Queued: {line}")
                if run:
                    if _has_pending_uploads(q) and not vault_passphrase:
                        print_info(
                            "Queued downloads were not run because pending uploads need "
                            "--vault-passphrase."
                        )
                        continue
                    from .queue_cmd import queue_run

                    ctx.invoke(queue_run, vault_passphrase=vault_passphrase, mfa_code=mfa_code)
    except KeyboardInterrupt:
        print_info("Watch stopped.")
        return


def _has_pending_uploads(queue: QueueManager) -> bool:
    return any(
        item.type == JobType.UPLOAD.value and item.status == JobStatus.PENDING.value
        for item in queue.items
    )
