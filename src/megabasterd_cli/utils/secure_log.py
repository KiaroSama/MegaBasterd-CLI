"""The one secure-open helper for log files, on Windows and on POSIX.

The invariant: a log file is owner-only *before* its first byte is written, or
file logging does not happen. There is no ordinary-open fallback anywhere on
this path, because a fallback is exactly how the guarantee was lost. The
launcher hardened its log with `Get-Acl`/`Set-Acl`/`SetAccessRuleProtection` -
Windows-only APIs. On POSIX that attempt failed, was swallowed, and the append
that followed created the file with the ambient umask (normally 0644).

Two rules follow from "before the first byte":

* The file is created explicitly, not as a side effect of the first write:
  `O_CREAT|O_EXCL|O_NOFOLLOW` with mode 0600 on POSIX, a protected owner-only
  DACL on Windows. Creating permissively and fixing it afterwards is not
  equivalent - it leaves a window in which anyone can read the log.
* The result is *verified* rather than assumed - `fstat` on the open descriptor
  on POSIX, the rendered DACL on Windows. A hardening call that silently failed
  used to leave a world-readable log behind a comment claiming otherwise.

A pre-existing path is tightened in place and re-verified, never unlinked and
replaced: the path is arbitrary and may be a file the caller cares about. If it
cannot be made owner-only, `InsecureLogFileError` is raised and nothing is
written.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys

OWNER_ONLY = 0o600

# Reading a DACL costs an `icacls` subprocess, so a file that has been hardened
# AND verified in this process is not re-verified on every appended line. Keyed
# on (st_dev, st_ino) from the open descriptor rather than on the path: this
# caches a *proven* result about one file, never the mere existence of a name.
# ponytail: per-process cache, drop it if a mid-run DACL change becomes a threat
# worth two subprocesses per log line.
_verified: set[tuple[int, int]] = set()

# Principals that must not appear in a log file's DACL. Matched against the ACE
# text only - never the leading path, which routinely contains "Users".
_BROAD_PRINCIPALS = ("Everyone", "BUILTIN\\Users", "Authenticated Users", "NT AUTHORITY\\Anonymous")


class InsecureLogFileError(OSError):
    """The log file could not be established as owner-only, so it must not be written.

    Subclasses `OSError` so callers that already treat log writing as
    non-fatal (`except OSError: pass`) keep degrading gracefully instead of
    crashing the CLI over a log file.
    """


# ---------------------------------------------------------------------------
# POSIX
# ---------------------------------------------------------------------------


def _verify_posix(fd: int, path: str) -> None:
    """Prove, on the open descriptor, that this is our own owner-only regular file.

    On the descriptor and not the path: anything checked by name can be swapped
    between the check and the write.
    """
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise InsecureLogFileError(f"log path is not a regular file: {path}")
    mode = stat.S_IMODE(info.st_mode)
    if mode != OWNER_ONLY:
        raise InsecureLogFileError(f"log file is {oct(mode)}, not {oct(OWNER_ONLY)}: {path}")
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and info.st_uid != geteuid():
        raise InsecureLogFileError(f"log file is owned by uid {info.st_uid}: {path}")


def _open_posix(path: str) -> int:
    # sys.platform (not os.name) so type checkers narrow away the branch that
    # cannot exist on the platform they are checking: O_NOFOLLOW and fchmod are
    # genuinely absent on Windows, and this function is genuinely never reached
    # there.
    if sys.platform == "win32":  # pragma: no cover - unreachable via open_secure
        raise InsecureLogFileError(f"the POSIX secure open is not available here: {path}")
    # O_NOFOLLOW on every open: a symlink planted at the log path must never
    # redirect the write, and must never be "handled" by falling back.
    flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, OWNER_ONLY)
    except FileExistsError:
        pass
    else:
        try:
            _verify_posix(fd, path)
        except BaseException:
            os.close(fd)
            raise
        return fd

    # Pre-existing: classify by lstat BEFORE opening, so a symlink or a special
    # file is rejected rather than opened and then reasoned about.
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        raise InsecureLogFileError(f"log path is a symlink: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise InsecureLogFileError(f"log path is not a regular file: {path}")

    fd = os.open(path, flags)
    try:
        os.fchmod(fd, OWNER_ONLY)
        _verify_posix(fd, path)
    except BaseException:
        os.close(fd)
        raise
    return fd


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------


def _windows_account() -> str:
    user = os.environ.get("USERNAME", "")
    domain = os.environ.get("USERDOMAIN", "")
    if not user:
        import getpass

        user = getpass.getuser()
    return f"{domain}\\{user}" if domain and user else user


def _icacls(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["icacls", *args],
        capture_output=True,
        text=True,
        timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _windows_harden(path: str) -> None:
    """Drop inheritance and grant only the current user.

    A non-zero exit is a failure, not a shrug: `check=False` here is what let a
    log file keep its inherited world-readable ACEs while the caller believed
    it had been hardened.
    """
    account = _windows_account()
    if not account:
        raise InsecureLogFileError(f"no current account to grant access to: {path}")
    # /inheritance:r drops the inherited (Users/Everyone) ACEs; /grant:r then
    # leaves the current account as the only entry.
    result = _icacls(path, "/inheritance:r", "/grant:r", f"{account}:(F)")
    if result.returncode != 0 and "\\" in account:
        # A domain-qualified name can fail to resolve on a workgroup machine.
        bare = account.split("\\")[-1]
        result = _icacls(path, "/inheritance:r", "/grant:r", f"{bare}:(F)")
    if result.returncode != 0:
        raise InsecureLogFileError(
            f"icacls failed with {result.returncode} while hardening {path}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )


def _windows_verify(path: str) -> None:
    """Read the resulting DACL back. Assuming it took is how this silently broke."""
    result = _icacls(path)
    if result.returncode != 0:
        raise InsecureLogFileError(
            f"icacls could not read the DACL of {path}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    # icacls prints the path first, then the ACEs. The path is not part of the
    # DACL and must not be scanned: "C:\\Users\\..." would match BUILTIN\\Users.
    aces = result.stdout
    if aces.startswith(path):
        aces = aces[len(path) :]
    if "(I)" in aces:
        raise InsecureLogFileError(f"log file still inherits ACEs: {path}")
    lowered = aces.lower()
    for principal in _BROAD_PRINCIPALS:
        if principal.lower() in lowered:
            raise InsecureLogFileError(f"log file grants {principal}: {path}")
    account = _windows_account().split("\\")[-1]
    if account and account.lower() not in lowered:
        raise InsecureLogFileError(f"log file does not grant the current user: {path}")


def _open_windows(path: str) -> int:
    flags = os.O_WRONLY | os.O_APPEND
    try:
        fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, OWNER_ONLY)
    except FileExistsError:
        # A pre-existing path is never trusted just for existing: it is
        # classified, hardened and verified before a single byte is appended.
        if os.path.islink(path) or not os.path.isfile(path):
            raise InsecureLogFileError(f"log path is not a regular file: {path}") from None
        fd = os.open(path, flags)
    # ponytail: the file exists with the directory's DACL for the microseconds
    # between O_EXCL and icacls. Closing that window needs CreateFileW with an
    # explicit SECURITY_ATTRIBUTES via ctypes - swap it in if the window matters.
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise InsecureLogFileError(f"log path is not a regular file: {path}")
        # Keyed on the file's identity, not its name. Rollover renames the log
        # away and recreates the same name as a brand-new file, so a name-keyed
        # cache would report the fresh primary as already hardened and hand back
        # a descriptor on a file that still carries the directory's inherited ACEs.
        identity = (info.st_dev, info.st_ino)
        if identity not in _verified:
            _windows_harden(path)
            _windows_verify(path)
            _verified.add(identity)
    except BaseException:
        os.close(fd)
        raise
    return fd


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def open_secure(path: str | os.PathLike[str]) -> int:
    """Return an append-mode descriptor on a *verified* owner-only file.

    The single secure-open implementation, shared by `append_line` and by the
    CLI's rotating file handler. Raises `InsecureLogFileError` (an `OSError`)
    rather than returning a descriptor on a file it could not secure.
    """
    target = os.fspath(path)
    return _open_windows(target) if os.name == "nt" else _open_posix(target)


def reject_if_unsafe_target(path: str | os.PathLike[str]) -> None:
    """Refuse a rotation destination that is a symlink or any non-regular file.

    Rollover renames onto these paths; a planted symlink there would otherwise
    make the next rollover hand the log to somebody else's file.
    """
    target = os.fspath(path)
    try:
        info = os.lstat(target)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise InsecureLogFileError(f"rotation target is a symlink: {target}")
    if not stat.S_ISREG(info.st_mode):
        raise InsecureLogFileError(f"rotation target is not a regular file: {target}")


def append_line(path: str | os.PathLike[str], line: str) -> None:
    """Append one already-redacted line, creating the file owner-only if needed."""
    fd = open_secure(path)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(line if line.endswith("\n") else line + "\n")
