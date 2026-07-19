"""Owner-only log files, from the first byte, on Windows and on POSIX.

The launcher hardened its log with `Get-Acl`/`Set-Acl`/`SetAccessRuleProtection`
- Windows-only APIs. On POSIX that attempt failed and was swallowed, so the
first append created the file with the ambient umask (normally 0644) and left it
world-readable. Python's own `open(path, "a")` had exactly the same problem.

So the file is created explicitly rather than as a side effect of the first
write: `O_CREAT|O_EXCL` with mode 0600 on POSIX, a protected owner-only DACL on
Windows. Creating permissively and chmod'ing afterwards is not equivalent - it
leaves a window in which anyone can read the log.
"""

from __future__ import annotations

import os
import stat
import subprocess

OWNER_ONLY = 0o600

_POSIX = os.name != "nt"
# Windows has no cheap stat()-equivalent for a DACL, so the owner-only DACL is
# re-applied once per path per process instead of parsed on every line.
_hardened: set[str] = set()


def _windows_harden(path: str) -> None:
    """Drop inheritance and grant only the current user. Idempotent."""
    user = os.environ.get("USERNAME", "")
    domain = os.environ.get("USERDOMAIN", "")
    account = f"{domain}\\{user}" if domain and user else user
    if not account:
        return
    subprocess.run(
        ["icacls", path, "/inheritance:r", "/grant:r", f"{account}:(F)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def is_owner_only(path: str) -> bool:
    """Whether an existing file is safe to append to.

    On Windows this also repairs the DACL, because the launcher legitimately
    creates the log a moment before Python opens it: deleting that file - the
    POSIX answer to an unsafe file - would throw away the launcher's own log.
    """
    if _POSIX:
        return stat.S_IMODE(os.lstat(path).st_mode) == OWNER_ONLY
    if path not in _hardened:
        _windows_harden(path)
        _hardened.add(path)
    return True


def _open_secure(path: str) -> int:
    create = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL
    # O_NOFOLLOW so a symlink planted at the log path cannot redirect the write.
    create |= getattr(os, "O_NOFOLLOW", 0)
    for _ in range(2):
        try:
            fd = os.open(path, create, OWNER_ONLY)
        except FileExistsError:
            if is_owner_only(path):
                return os.open(path, create & ~(os.O_CREAT | os.O_EXCL), OWNER_ONLY)
            # An unsafe pre-existing file is never trusted: it may be a planted
            # link or simply world-readable. Replaced, not appended to.
            os.unlink(path)
            continue
        if not _POSIX:
            _windows_harden(path)
            _hardened.add(path)
        return fd
    raise OSError(f"could not create an owner-only log file: {path}")


def append_line(path: str | os.PathLike[str], line: str) -> None:
    """Append one already-redacted line, creating the file owner-only if needed."""
    fd = _open_secure(os.fspath(path))
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(line if line.endswith("\n") else line + "\n")
