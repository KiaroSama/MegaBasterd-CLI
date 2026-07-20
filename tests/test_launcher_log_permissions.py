"""Log files must be owner-only from the first byte on every platform.

`Write-RunLog` hardened the launcher log with `Get-Acl`, `Set-Acl` and
`SetAccessRuleProtection` - Windows-only APIs. On Linux/macOS that block threw,
the `catch` swallowed it, and the `Add-Content` that followed created the file
with the ambient umask: normally 0644, i.e. readable by every local account,
for the whole run and afterwards. "Owner-only from creation" was a Windows-only
guarantee, and the redaction in front of it does not help against a log that
also carries paths, account labels and command shapes.

The file is now created explicitly instead of being brought into existence as a
side effect of the first append: mode 0600 at creation time on POSIX (never
0644-then-chmod, which leaves a readable window), a protected owner-only DACL on
Windows. `utils.secure_log` is that one place for Python; Run.ps1 performs the
same two-branch creation itself, because `Write-RunLog` runs before the launcher
has established that a usable Python interpreter even exists.
"""

from __future__ import annotations

import os
import subprocess
import uuid
from pathlib import Path

import pytest

from megabasterd_cli.utils import secure_log
from tests.launcher_helpers import (
    OWNER_ONLY,
    RUN_PS1,
    posix_only,
    pwsh,
    requires_pwsh,
    windows_only,
)
from tests.launcher_helpers import artifacts as _logs
from tests.launcher_helpers import mode as _mode

SECRET = "SENTINEL-PW-4471"

# Every test here spawns the real Run.ps1, which may create and install into
# the project .venv. That is one shared resource, so they all run on a single
# xdist worker (--dist loadgroup) rather than racing each other over it.
pytestmark = pytest.mark.xdist_group("launcher_subprocess")


def _launch(args: list[str], log_dir: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["MEGABASTERD_LAUNCHER_LOG_DIR"] = str(log_dir)
    env["MEGABASTERD_NO_PAUSE"] = "1"
    return subprocess.run(
        [pwsh, "-NoProfile", "-File", str(RUN_PS1), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )


def _acl(path: Path) -> str:
    """Windows: the file's ACL, rendered as SDDL-ish text for assertions."""
    probe = subprocess.run(
        [
            pwsh,
            "-NoProfile",
            "-Command",
            f"$a = Get-Acl -LiteralPath '{path}'; "
            "$a.AreAccessRulesProtected; "
            "$a.Access | ForEach-Object { $_.IdentityReference.Value }",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return probe.stdout


# ---------------------------------------------------------------------------
# POSIX: the platform the old implementation silently skipped
# ---------------------------------------------------------------------------


@posix_only
@requires_pwsh
def test_every_log_the_launcher_produces_is_0600_on_posix(tmp_path):
    """0644 for the whole run was the bug; 0600 must hold from creation."""
    log_dir = tmp_path / f"logs-{uuid.uuid4().hex[:8]}"
    log_dir.mkdir()

    _launch(["--help"], log_dir)

    produced = _logs(log_dir)
    assert produced, "no artifacts were produced - this check would prove nothing"
    widened = {p.name: oct(_mode(p)) for p in produced if _mode(p) != OWNER_ONLY}
    assert widened == {}, f"log files are not owner-only: {widened}"


@posix_only
def test_appending_never_widens_the_mode_on_posix(tmp_path):
    """Every later line reuses the file; none of them may re-create it."""
    path = tmp_path / "launcher.log"

    secure_log.append_line(path, "first")
    assert _mode(path) == OWNER_ONLY, oct(_mode(path))

    for index in range(5):
        secure_log.append_line(path, f"line {index}")
        assert _mode(path) == OWNER_ONLY, oct(_mode(path))

    assert path.read_text(encoding="utf-8").splitlines()[0] == "first"


@posix_only
def test_an_unsafe_pre_existing_file_is_tightened_not_replaced_on_posix(tmp_path):
    """Tightened in place, never unlinked and recreated.

    This used to assert the opposite - that the pre-existing file was replaced.
    Unlinking is the wrong answer for an *arbitrary* pre-existing path: the log
    path is attacker-influenceable, so unlink-and-replace turns a permission
    problem into a file-deletion primitive. `fchmod` on the open descriptor
    closes the permission hole without destroying anything, and the descriptor
    is re-verified before a byte is written. The assertion below is therefore
    stronger than the one it replaces: the mode must be fixed AND the original
    file must still be the same file.
    """
    path = tmp_path / "planted.log"
    path.write_text("planted\n", encoding="utf-8")
    path.chmod(0o666)
    inode = path.lstat().st_ino

    secure_log.append_line(path, "ours")

    assert _mode(path) == OWNER_ONLY, oct(_mode(path))
    assert path.lstat().st_ino == inode, "the pre-existing file was replaced, not tightened"
    assert "ours" in path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Windows: the behaviour that already existed must not regress
# ---------------------------------------------------------------------------


@windows_only
@requires_pwsh
def test_every_log_the_launcher_produces_is_owner_only_on_windows(tmp_path):
    log_dir = tmp_path / f"logs-{uuid.uuid4().hex[:8]}"
    log_dir.mkdir()

    _launch(["--help"], log_dir)

    produced = _logs(log_dir)
    assert produced, "no artifacts were produced - this check would prove nothing"
    for path in produced:
        rendered = _acl(path)
        assert rendered.splitlines()[:1] == ["True"], f"{path.name} inherits ACLs: {rendered!r}"
        assert (
            os.environ["USERNAME"].lower() in rendered.lower()
        ), f"the current user cannot reach {path.name}: {rendered!r}"
        for broad in ("Everyone", "BUILTIN\\Users", "Authenticated Users"):
            assert broad not in rendered, f"{path.name} grants {broad}: {rendered!r}"


@windows_only
@requires_pwsh
def test_an_unsafe_pre_existing_file_is_hardened_on_windows(tmp_path):
    path = tmp_path / "planted.log"
    path.write_text("planted\n", encoding="utf-8")

    secure_log.append_line(path, "ours")

    rendered = _acl(path)
    assert rendered.splitlines()[:1] == ["True"], f"inherited ACLs survived: {rendered!r}"
    for broad in ("Everyone", "BUILTIN\\Users", "Authenticated Users"):
        assert broad not in rendered, f"grants {broad}: {rendered!r}"


# ---------------------------------------------------------------------------
# Every platform
# ---------------------------------------------------------------------------


def test_the_helper_creates_exclusively_and_asks_for_0600(tmp_path, monkeypatch):
    """Runnable on Windows too, where the mode assertion above cannot run.

    O_EXCL matters as much as the mode: creating and then chmod'ing leaves a
    window in which the file is world-readable, and following a planted symlink
    would write the log somewhere else entirely.
    """
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
    if hasattr(os, "O_NOFOLLOW"):
        assert flags & os.O_NOFOLLOW, oct(flags)


def test_the_launcher_menu_log_creates_an_owner_only_file(tmp_path, monkeypatch):
    """`open(path, "a")` here created a 0644 file whenever Run.ps1 had not.

    The secure creation must not have been bought by dropping the redaction the
    line already went through, so the payload is one `redact_text` covers.
    """
    from megabasterd_cli import launcher_menu

    path = tmp_path / "menu.log"
    monkeypatch.setenv("MEGABASTERD_LAUNCHER_LOG_FILE", str(path))

    launcher_menu.log("INFO", f"opening https://mega.nz/file/ABCDEFGH#{SECRET}")

    assert path.exists()
    if os.name == "nt":
        if pwsh:
            assert _acl(path).splitlines()[:1] == ["True"], _acl(path)
    else:
        assert _mode(path) == OWNER_ONLY, oct(_mode(path))
    assert SECRET not in path.read_text(encoding="utf-8"), "redaction was lost"


@requires_pwsh
def test_no_secret_and_no_transcript_survive_a_real_run(tmp_path):
    log_dir = tmp_path / f"logs-{uuid.uuid4().hex[:8]}"
    log_dir.mkdir()

    _launch(["config", "get", "download_path", "--password", SECRET], log_dir)

    produced = _logs(log_dir)
    assert produced, "no artifacts were produced - this scan would prove nothing"
    for path in produced:
        assert "transcript" not in path.name.lower(), f"a transcript came back: {path.name}"
        assert SECRET not in path.read_text(encoding="utf-8", errors="ignore"), path.name
