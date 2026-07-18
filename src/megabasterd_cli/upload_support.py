"""Shared upload building blocks: post-success pipeline and quota ledger.

Split out of `upload_cmd.py`, which had grown past 800 lines and was being
imported BY another command module (`queue_cmd` needed
`finalize_upload_success`). A command module importing another command module
is backwards; both now depend on this one instead.

Neither piece touches Click: `finalize_upload_success` is the post-transfer
pipeline every upload mode shares, and `QuotaLedger` is pure thread-safe
free-space accounting.
"""

from __future__ import annotations

import threading
from pathlib import Path

from .core.client import MegaClient
from .core.errors import MegaError
from .core.uploader import UploadResult
from .ui.machine_output import MachineOutput
from .ui.prompts import print_error, print_info, print_success
from .utils.helpers import format_bytes
from .utils.hooks import append_upload_log, run_post_transfer_command
from .utils.redaction import redact_text


def finalize_upload_success(
    cfg,
    client: MegaClient,
    result: UploadResult,
    local_path: Path,
    *,
    share: bool = False,
    share_password: str | None = None,
    note=None,
    machine: MachineOutput | None = None,
) -> str | None:
    """Centralized post-upload success pipeline used by EVERY upload mode
    (sequential, parallel, flat/structured directory, queue, auto-account).

    Handles success output, the optional public/password-protected share
    link, the JSONL upload log, the post-transfer command, and account
    attribution. A share/hook failure is reported separately and never
    converts a successful transfer into a failure. Returns the share link.

    When `note` (a `(kind, message)` callback) is given, user-facing messages
    are buffered there (thread-safe) so a live progress view is not torn up
    and the caller prints them after closing.
    """

    def say(kind: str, message: str) -> None:
        if note is not None:
            note(kind, message)
        else:
            {"success": print_success, "info": print_info, "error": print_error}[kind](message)

    say(
        "success",
        f"{result.name} ({format_bytes(result.size)}) in {result.elapsed_seconds:.1f}s",
    )
    link: str | None = None
    if share:
        try:
            link = client.export_link(result.file_handle, password=share_password)
            say("info", f"Share link: {link}")
        except MegaError as exc:
            # Reported separately: the upload itself succeeded.
            say(
                "error", f"Could not generate share link for {result.name}: {redact_text(str(exc))}"
            )
    append_upload_log(
        cfg.upload_log_path,
        local_path=local_path,
        file_handle=result.file_handle,
        size=result.size,
        elapsed_seconds=result.elapsed_seconds,
        public_link=link,
        account=client.session.email if client.session else None,
    )
    if machine is not None:
        machine.emit(
            event="result",
            type="upload",
            status="success",
            name=result.name,
            path=str(local_path),
            size=result.size,
            elapsed_seconds=round(result.elapsed_seconds, 2),
            handle=result.file_handle,
            account=client.session.email if client.session else None,
            share_link=link,
        )
    run_post_transfer_command(cfg.run_command, local_path)
    return link


class QuotaLedger:
    """Thread-safe free-space ledger driving `--auto-account` selection.

    Files are NOT pre-bound to accounts: the account is chosen immediately
    before each file starts via `reserve()`, which atomically deducts the
    expected bytes so parallel reservations can never overcommit one
    account. A successful upload keeps its reservation; a non-quota failure
    `release()`s it; a `QuotaError` triggers `reconcile_free()` with the account's
    LIVE quota so the failed file and every not-yet-started file are
    re-planned against fresh numbers instead of the stale cache.
    """

    def __init__(self, free: dict[str, int]):
        self._free = {email: max(0, int(amount)) for email, amount in free.items()}
        self._lock = threading.Lock()

    def reserve(self, size: int, exclude: set[str] | frozenset[str] = frozenset()) -> str | None:
        """Pick the account with the most known free space >= size and
        atomically deduct the reservation; None when no account fits."""
        with self._lock:
            candidates = [
                (free, email)
                for email, free in self._free.items()
                if free >= size and email not in exclude
            ]
            if not candidates:
                return None
            free, email = max(candidates)
            self._free[email] = free - size
            return email

    def release(self, email: str, size: int) -> None:
        """Return a reservation after a non-quota failure."""
        with self._lock:
            if email in self._free:
                self._free[email] += size

    def reconcile_free(self, email: str, free: int) -> None:
        """Correct an account's balance from a live quota read — downward only.

        A live read cannot see the reservations of files still in flight, so
        raising the balance from it would hand back space another file already
        reserved. Concurrent QuotaError refreshes for one account therefore can
        never increase available space; they only shrink it (0 = unusable).
        """
        with self._lock:
            current = self._free.get(email, 0)
            self._free[email] = min(current, max(0, int(free)))

    def free_of(self, email: str) -> int | None:
        with self._lock:
            return self._free.get(email)
