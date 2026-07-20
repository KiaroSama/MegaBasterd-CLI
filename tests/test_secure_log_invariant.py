"""A log file is owner-only before its first byte, or file logging does not happen.

The old code treated hardening as best-effort: `logger._owner_only` ran inside
`with suppress(OSError)` and `super()._open()` executed regardless, so every
failure fell back to an ordinary umask-controlled open. On POSIX that was
directly exploitable - `O_NOFOLLOW` rejected a planted symlink, the error was
swallowed, and the fallback open then followed the very symlink `O_NOFOLLOW`
had just refused. `secure_log` had the mirror-image problem: `is_owner_only`
returned `True` unconditionally on Windows without ever reading the resulting
DACL, and an untrusted pre-existing path was `unlink`ed and replaced.

These tests use real filesystem objects - real symlinks, real FIFOs, real mode
bits - because mocking the property under test proves nothing about it.
"""

from __future__ import annotations

import builtins
import contextlib
import logging
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from megabasterd_cli.utils import secure_log
from megabasterd_cli.utils.logger import OwnerOnlyRotatingFileHandler, setup_logging
from megabasterd_cli.utils.secure_log import InsecureLogFileError

OWNER_ONLY = 0o600
SENTINEL = "SENTINEL-PW-4471"

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits and symlink semantics")
windows_only = pytest.mark.skipif(os.name != "nt", reason="Windows DACLs")


@pytest.fixture
def logging_teardown():
    yield
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    root.filters.clear()


@pytest.fixture(autouse=True)
def reset_warn_once():
    """ "At most one warning" is per-process, so each test needs a clean slate."""
    from megabasterd_cli.utils import logger as logger_module

    logger_module._file_logging_warned = False
    secure_log._verified.clear()
    yield
    logger_module._file_logging_warned = False
    secure_log._verified.clear()


@pytest.fixture
def umask_zero():
    """A strict ambient umask would hide a permissive creation."""
    if os.name == "nt":
        yield
        return
    previous = os.umask(0o000)
    try:
        yield
    finally:
        os.umask(previous)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


class _OpenSpy:
    """Records every ordinary open that the secure path must never perform."""

    def __init__(self, monkeypatch):
        self.calls: list[str] = []
        real_open = builtins.open
        real_handler_open = logging.handlers.RotatingFileHandler._open

        def spy_open(file, *args, **kwargs):
            self.calls.append(f"builtins.open({file!r})")
            return real_open(file, *args, **kwargs)

        def spy_handler_open(handler):
            self.calls.append("RotatingFileHandler._open")
            return real_handler_open(handler)

        monkeypatch.setattr(builtins, "open", spy_open)
        monkeypatch.setattr(logging.handlers.RotatingFileHandler, "_open", spy_handler_open)

    def unsafe(self, path: Path) -> list[str]:
        target = str(path)
        return [c for c in self.calls if "RotatingFileHandler._open" in c or target in c]


# ---------------------------------------------------------------------------
# 1. A new primary log is owner-only at creation, verified before the first byte
# ---------------------------------------------------------------------------


@posix_only
def test_a_new_log_is_created_0600_and_verified_before_the_first_byte(
    tmp_path, umask_zero, monkeypatch
):
    path = tmp_path / "cli.log"
    order: list[str] = []
    real_fstat, real_fdopen = os.fstat, os.fdopen

    def spy_fstat(fd, *a, **k):
        order.append("fstat")
        return real_fstat(fd, *a, **k)

    def spy_fdopen(fd, *a, **k):
        order.append("fdopen")
        return real_fdopen(fd, *a, **k)

    monkeypatch.setattr(os, "fstat", spy_fstat)
    monkeypatch.setattr(os, "fdopen", spy_fdopen)

    secure_log.append_line(path, "hello")

    info = path.lstat()
    assert stat.S_ISREG(info.st_mode), "not a regular file"
    assert stat.S_IMODE(info.st_mode) == OWNER_ONLY, oct(stat.S_IMODE(info.st_mode))
    assert order.index("fstat") < order.index(
        "fdopen"
    ), f"the descriptor was handed to a writer before it was verified: {order}"


# ---------------------------------------------------------------------------
# 2. A permissive pre-existing file is tightened and verified, never written permissive
# ---------------------------------------------------------------------------


@posix_only
def test_a_permissive_pre_existing_file_is_never_written_while_permissive(tmp_path, umask_zero):
    path = tmp_path / "planted.log"
    path.write_text("planted\n", encoding="utf-8")
    path.chmod(0o666)

    try:
        secure_log.append_line(path, "ours")
    except InsecureLogFileError:
        assert "ours" not in path.read_text(encoding="utf-8"), "rejected but written anyway"
        return

    assert _mode(path) == OWNER_ONLY, f"appended to a {oct(_mode(path))} file"
    assert "ours" in path.read_text(encoding="utf-8")


@posix_only
def test_a_permissive_pre_existing_file_is_not_unlinked_and_replaced(tmp_path, umask_zero):
    """Unlink-and-replace destroys an arbitrary pre-existing path; tighten instead."""
    path = tmp_path / "planted.log"
    path.write_text("planted\n", encoding="utf-8")
    path.chmod(0o666)
    inode = path.lstat().st_ino

    with contextlib.suppress(InsecureLogFileError):
        secure_log.append_line(path, "ours")

    assert path.exists(), "the pre-existing path was removed"
    assert path.lstat().st_ino == inode, "the pre-existing file was replaced, not tightened"


# ---------------------------------------------------------------------------
# 3. A symlink planted at the log path is never followed
# ---------------------------------------------------------------------------


@posix_only
def test_a_symlink_at_the_log_path_is_not_followed_by_append_line(tmp_path, umask_zero):
    target = tmp_path / "victim.txt"
    target.write_text("victim contents\n", encoding="utf-8")
    before = target.read_bytes()
    link = tmp_path / "cli.log"
    link.symlink_to(target)

    with pytest.raises(InsecureLogFileError):
        secure_log.append_line(link, "ours")

    assert target.read_bytes() == before, "the write followed the planted symlink"


@posix_only
def test_a_symlink_at_the_log_path_is_not_followed_by_the_rotating_handler(
    tmp_path, umask_zero, monkeypatch
):
    target = tmp_path / "victim.txt"
    target.write_text("victim contents\n", encoding="utf-8")
    before = target.read_bytes()
    link = tmp_path / "cli.log"
    link.symlink_to(target)
    spy = _OpenSpy(monkeypatch)

    with pytest.raises(InsecureLogFileError):
        OwnerOnlyRotatingFileHandler(str(link), maxBytes=10_000, backupCount=2, encoding="utf-8")

    assert target.read_bytes() == before, "the handler wrote through the planted symlink"
    assert spy.unsafe(link) == [], f"an unsafe fallback open ran: {spy.unsafe(link)}"


# ---------------------------------------------------------------------------
# 4. Non-regular paths are rejected outright
# ---------------------------------------------------------------------------


@posix_only
@pytest.mark.parametrize("kind", ["directory", "fifo"])
def test_a_non_regular_path_is_rejected(tmp_path, umask_zero, kind):
    path = tmp_path / "cli.log"
    if kind == "directory":
        path.mkdir()
    else:
        os.mkfifo(path, 0o600)

    with pytest.raises(OSError):
        secure_log.append_line(path, "ours")

    assert not stat.S_ISREG(path.lstat().st_mode), "the special file was replaced"


# ---------------------------------------------------------------------------
# 5. A failed secure open never falls back to an ordinary open
# ---------------------------------------------------------------------------


@posix_only
@pytest.mark.parametrize("victim", ["open", "fchmod", "fstat"])
def test_a_failed_secure_open_never_falls_back_to_an_ordinary_open(
    tmp_path, umask_zero, monkeypatch, victim
):
    path = tmp_path / "cli.log"
    if victim in {"fchmod", "fstat"}:
        # These only run once the descriptor exists, so the file must pre-exist
        # for `fchmod` and must be creatable for `fstat`.
        path.write_text("", encoding="utf-8")
        path.chmod(0o666)
    spy = _OpenSpy(monkeypatch)

    def boom(*args, **kwargs):
        raise OSError(13, "simulated failure")

    monkeypatch.setattr(os, victim, boom)

    with pytest.raises(OSError):
        secure_log.append_line(path, "ours")

    assert spy.unsafe(path) == [], f"an unsafe fallback open ran: {spy.unsafe(path)}"
    if path.exists():
        assert "ours" not in path.read_text(encoding="utf-8"), "content was written anyway"


@posix_only
def test_a_failed_handler_open_never_calls_the_base_class_open(tmp_path, umask_zero, monkeypatch):
    path = tmp_path / "cli.log"
    spy = _OpenSpy(monkeypatch)
    monkeypatch.setattr(
        secure_log, "open_secure", lambda p: (_ for _ in ()).throw(InsecureLogFileError("nope"))
    )

    with pytest.raises(InsecureLogFileError):
        OwnerOnlyRotatingFileHandler(str(path), maxBytes=10_000, backupCount=2, encoding="utf-8")

    assert "RotatingFileHandler._open" not in spy.calls, "the unsafe superclass open ran"
    assert not path.exists(), "the log file was created despite a failed hardening"


# ---------------------------------------------------------------------------
# 6. Rotation preserves the invariant for primary, backups, and the fresh primary
# ---------------------------------------------------------------------------


@posix_only
def test_rotation_leaves_every_file_owner_only(tmp_path, umask_zero, logging_teardown):
    log_file = tmp_path / "cli.log"
    setup_logging(level="DEBUG", log_file=log_file, quiet=True, max_bytes=200, backup_count=2)
    handler = next(h for h in logging.getLogger().handlers if hasattr(h, "doRollover"))
    for index in range(40):
        logging.getLogger("t").warning("line %d padded to force a rollover", index)
    handler.flush()

    produced = [log_file, log_file.with_name("cli.log.1")]
    assert produced[1].exists(), "no rotation happened - this test would prove nothing"
    for path in produced:
        assert _mode(path) == OWNER_ONLY, f"{path.name} is {oct(_mode(path))}"


@posix_only
def test_a_symlink_at_a_rotation_destination_makes_rollover_fail_closed(
    tmp_path, umask_zero, logging_teardown, monkeypatch
):
    victim = tmp_path / "victim.txt"
    victim.write_text("victim contents\n", encoding="utf-8")
    before = victim.read_bytes()
    log_file = tmp_path / "cli.log"

    setup_logging(level="DEBUG", log_file=log_file, quiet=True, max_bytes=200, backup_count=2)
    handler = next(h for h in logging.getLogger().handlers if hasattr(h, "doRollover"))
    (tmp_path / "cli.log.1").symlink_to(victim)
    spy = _OpenSpy(monkeypatch)

    with pytest.raises(InsecureLogFileError):
        handler.doRollover()

    assert victim.read_bytes() == before, "rollover followed the planted symlink"
    assert (tmp_path / "cli.log.1").is_symlink(), "the planted symlink was replaced"
    assert spy.calls == [] or spy.unsafe(log_file) == [], "an unsafe fallback open ran"
    assert _mode(log_file) == OWNER_ONLY


@posix_only
def test_a_rollover_failure_disables_the_file_handler_instead_of_writing(
    tmp_path, umask_zero, logging_teardown
):
    victim = tmp_path / "victim.txt"
    victim.write_text("victim contents\n", encoding="utf-8")
    before = victim.read_bytes()
    log_file = tmp_path / "cli.log"

    setup_logging(level="DEBUG", log_file=log_file, quiet=True, max_bytes=200, backup_count=2)
    (tmp_path / "cli.log.1").symlink_to(victim)

    for index in range(60):
        logging.getLogger("t").warning("line %d padded to force a rollover", index)

    assert victim.read_bytes() == before, "the emit path followed the planted symlink"


# ---------------------------------------------------------------------------
# 7-9. Windows DACLs
# ---------------------------------------------------------------------------


def _icacls(path: Path) -> str:
    return subprocess.run(["icacls", str(path)], capture_output=True, text=True, timeout=60).stdout


@windows_only
def test_a_pre_existing_windows_file_is_not_blindly_trusted(tmp_path, monkeypatch):
    """`if os.path.exists(path): return` trusted whatever was already there."""
    path = tmp_path / "planted.log"
    path.write_text("planted\n", encoding="utf-8")
    assert "(I)" in _icacls(path), "the fixture already lacks inherited ACEs - it proves nothing"

    hardened: list[str] = []
    real = secure_log._windows_harden
    monkeypatch.setattr(
        secure_log,
        "_windows_harden",
        lambda p: (hardened.append(p), real(p))[1],
    )

    secure_log.append_line(path, "ours")

    assert hardened, "the pre-existing file was accepted without hardening"
    assert "(I)" not in _icacls(path), f"inherited ACEs survived:\n{_icacls(path)}"


@windows_only
def test_a_failing_icacls_writes_nothing_and_does_not_fall_back(tmp_path, monkeypatch):
    path = tmp_path / "cli.log"
    spy = _OpenSpy(monkeypatch)

    class _Failed:
        returncode = 5
        stdout = ""
        stderr = "Access is denied."

    monkeypatch.setattr(secure_log.subprocess, "run", lambda *a, **k: _Failed())

    with pytest.raises(InsecureLogFileError):
        secure_log.append_line(path, "ours")

    assert spy.unsafe(path) == [], f"an unsafe fallback open ran: {spy.unsafe(path)}"
    if path.exists():
        assert path.read_text(encoding="utf-8") == "", "content was written despite failed ACLs"


@windows_only
def test_successful_hardening_disables_inheritance_and_keeps_the_current_user(tmp_path):
    path = tmp_path / "cli.log"

    secure_log.append_line(path, "ours")

    acl = _icacls(path)
    body = acl[len(str(path)) :] if acl.startswith(str(path)) else acl
    assert "(I)" not in body, f"inheritance is still enabled:\n{acl}"
    for broad in ("Everyone", "BUILTIN\\Users", "Authenticated Users"):
        assert broad not in body, f"{broad} still has access:\n{acl}"
    assert os.environ["USERNAME"].lower() in body.lower(), f"the owner lost access:\n{acl}"
    assert path.read_text(encoding="utf-8").strip() == "ours"


# ---------------------------------------------------------------------------
# 10-11. Every platform
# ---------------------------------------------------------------------------


def test_a_hardening_failure_degrades_to_console_and_leaves_the_file_untouched(
    tmp_path, monkeypatch, capsys, logging_teardown
):
    log_file = tmp_path / "cli.log"
    log_file.write_bytes(b"pre-existing bytes\n")

    def refuse(path):
        raise InsecureLogFileError(f"could not secure {path}")

    monkeypatch.setattr(secure_log, "open_secure", refuse)

    setup_logging(level="DEBUG", log_file=log_file, quiet=False)
    logging.getLogger("t").warning("still alive")

    root = logging.getLogger()
    assert root.handlers, "the CLI lost every handler over a file-logging failure"
    assert not any(isinstance(h, OwnerOnlyRotatingFileHandler) for h in root.handlers)
    assert log_file.read_bytes() == b"pre-existing bytes\n", "the unsafe file was written to"
    assert "file logging" in capsys.readouterr().err.lower(), "no warning was emitted"


def test_only_one_sanitized_warning_reaches_stderr(tmp_path, monkeypatch, capsys, logging_teardown):
    """The warning names the failure, not the secret that happened to be in the path."""
    log_file = tmp_path / f"user@example.com-{SENTINEL}.log"

    def refuse(path):
        raise InsecureLogFileError(f"could not secure {path} (password: {SENTINEL})")

    monkeypatch.setattr(secure_log, "open_secure", refuse)

    setup_logging(level="DEBUG", log_file=log_file, quiet=False)
    for _ in range(5):
        logging.getLogger("t").warning("still alive")

    err = capsys.readouterr().err
    assert SENTINEL not in err, f"a secret leaked into the warning: {err!r}"
    assert "user@example.com" not in err, f"an account identifier leaked: {err!r}"
    assert err.lower().count("file logging") == 1, f"more than one warning: {err!r}"


def test_the_shared_helper_is_the_only_secure_open_implementation():
    """One helper, used by both callers - not two partially-equivalent copies."""
    from megabasterd_cli.utils import logger

    assert not hasattr(logger, "_owner_only"), "logger keeps a private second implementation"
    assert hasattr(secure_log, "open_secure")
    source = Path(logger.__file__).read_text(encoding="utf-8")
    assert "defence in depth" not in source.lower(), "hardening is an invariant, not a bonus"


def test_the_secure_open_flags_are_exclusive_and_never_follow(tmp_path, monkeypatch):
    seen: list[tuple[int, int]] = []
    real_open = os.open

    def spy(path, flags, mode=0o777, **kwargs):
        seen.append((flags, mode))
        return real_open(path, flags, mode, **kwargs)

    monkeypatch.setattr(os, "open", spy)
    secure_log.append_line(tmp_path / "new.log", "hello")

    flags, mode = seen[0]
    assert mode == OWNER_ONLY, oct(mode)
    assert flags & os.O_CREAT and flags & os.O_EXCL, oct(flags)
    if sys.platform != "win32":
        assert flags & os.O_NOFOLLOW, oct(flags)
