"""The launcher log is owner-only before its first byte, or it is not written.

`New-SecureLogFile` used to `Remove-Item -Force` whatever it found sitting at
this run's log path. Unlinking an arbitrary pre-existing entry is not a fix: a
planted symlink or junction gets destroyed (or, with the wrong cmdlet, followed)
and the "secured" file that replaces it is one an attacker just made the
launcher create. `Test-OwnerOnlyLogFile` also asked only whether the Windows
DACL was protected, which says nothing about a reparse point, a directory, or a
protected DACL that still hands `BUILTIN\\Users` a read ACE. And
`Write-SecureLogLine` called `Add-Content` whether or not securing had worked.

The invariant is now enforced, not attempted: anything at the log path that is
not provably a safe owner-only regular file fails closed, file logging switches
off for the rest of the run with one sanitized console warning, and the console
output the user actually reads keeps going.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import uuid
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RUN_PS1 = REPO / "Run.ps1"
RUN_TEXT = RUN_PS1.read_text(encoding="utf-8")

SECRET = "SENTINEL-PW-8842"
MEGA_KEY = "SENTINELKEY9911"

pwsh = shutil.which("pwsh") or shutil.which("powershell")
requires_pwsh = pytest.mark.skipif(pwsh is None, reason="PowerShell is not available")
posix_only = pytest.mark.skipif(
    os.name == "nt", reason="POSIX file modes are not a Windows concept"
)
windows_only = pytest.mark.skipif(os.name != "nt", reason="ACL check is Windows-specific")

OWNER_ONLY = 0o600
BROAD = ("Everyone", "BUILTIN\\Users", "Authenticated Users")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _launch(args: list[str], log_dir: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["MEGABASTERD_LAUNCHER_LOG_DIR"] = str(log_dir)
    env["MEGABASTERD_NO_PAUSE"] = "1"
    return subprocess.run(
        [pwsh, "-NoProfile", "-File", str(RUN_PS1), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=300,
    )


def _artifacts(log_dir: Path) -> list[Path]:
    return [p for p in log_dir.rglob("*") if p.is_file()]


def _extract_function(name: str) -> str:
    """Pull one PowerShell function out of Run.ps1 by brace matching."""
    start = RUN_TEXT.index(f"function {name} {{")
    depth = 0
    for index in range(start, len(RUN_TEXT)):
        if RUN_TEXT[index] == "{":
            depth += 1
        elif RUN_TEXT[index] == "}":
            depth -= 1
            if depth == 0:
                return RUN_TEXT[start : index + 1]
    raise AssertionError(f"unbalanced braces in {name}")


def _code_of(name: str) -> str:
    """The function with comment lines dropped, so prose cannot satisfy an assertion."""
    return "\n".join(
        line for line in _extract_function(name).splitlines() if not line.lstrip().startswith("#")
    )


HARNESS_PRELUDE = """param([string] $Target, [string] $Line = 'harness line')
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:IsWindowsHost = ([System.Environment]::OSVersion.Platform -eq "Win32NT")
$script:UnixOwnerOnly = if ($script:IsWindowsHost) { $null } else {
    [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
}
$script:SecuredLogs = @{}
$script:LauncherFileLoggingDisabled = $false
$LogDir = Split-Path -Parent $Target
"""

HARNESS_FUNCTIONS = (
    "Get-RedactedText",
    "Disable-LauncherFileLogging",
    "Test-OwnerOnlyLogFile",
    "New-SecureLogFile",
    "Write-SecureLogLine",
)


def _write_harness(tmp_path: Path) -> Path:
    """Drive the real writer in isolation.

    The launcher's own log path carries a millisecond RunId, so a test cannot
    plant anything at it from the outside. The functions are lifted out of
    Run.ps1 verbatim - same trick test_launcher_transcript_redaction.py uses -
    so what runs here is the shipped code, not a copy of it.
    """
    body = HARNESS_PRELUDE + "\n".join(_extract_function(n) for n in HARNESS_FUNCTIONS)
    body += "\nWrite-SecureLogLine $Target $Line\n"
    body += '"DISABLED=$($script:LauncherFileLoggingDisabled)"\n'
    script = tmp_path / "harness.ps1"
    script.write_text(body, encoding="utf-8")
    return script


def _run_harness(tmp_path: Path, target: Path, line: str = "harness line"):
    proc = subprocess.run(
        [pwsh, "-NoProfile", "-File", str(_write_harness(tmp_path)), str(target), line],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    return proc


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def _acl(path: Path) -> str:
    probe = subprocess.run(
        [
            pwsh,
            "-NoProfile",
            "-Command",
            f"$a = Get-Acl -LiteralPath '{path}'; "
            "$a.AreAccessRulesProtected; "
            "$a.Access | ForEach-Object "
            '{ "$($_.IdentityReference.Value) :: $($_.FileSystemRights)" }',
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return probe.stdout


# ---------------------------------------------------------------------------
# 1. a fresh run is owner-only from creation
# ---------------------------------------------------------------------------


@windows_only
@requires_pwsh
def test_fresh_launcher_log_is_owner_only_from_creation_on_windows(tmp_path):
    log_dir = tmp_path / f"logs-{uuid.uuid4().hex[:8]}"
    log_dir.mkdir()

    _launch(["--help"], log_dir)

    logs = list(log_dir.glob("launcher-*.log"))
    assert logs, "no launcher log was produced - this check would prove nothing"
    rendered = _acl(logs[0])
    assert rendered.splitlines()[:1] == ["True"], f"log inherits ACLs: {rendered!r}"
    for broad in BROAD:
        assert broad not in rendered, f"log grants {broad}: {rendered!r}"


@posix_only
@requires_pwsh
def test_fresh_launcher_log_is_mode_0600_on_posix(tmp_path):
    """0644 via the ambient umask was the bug; nothing wider than 0600 may exist."""
    log_dir = tmp_path / f"logs-{uuid.uuid4().hex[:8]}"
    log_dir.mkdir()

    _launch(["--help"], log_dir)

    logs = list(log_dir.glob("launcher-*.log"))
    assert logs, "no launcher log was produced - this check would prove nothing"
    assert _mode(logs[0]) == OWNER_ONLY, oct(_mode(logs[0]))


# ---------------------------------------------------------------------------
# 2. a pre-existing UNSAFE regular file
# ---------------------------------------------------------------------------


@requires_pwsh
def test_a_permissive_pre_existing_file_is_never_appended_to(tmp_path):
    """Hardened before the first append, or rejected. Never written while wide open."""
    planted = tmp_path / "planted.log"
    planted.write_text("planted content\n", encoding="utf-8")
    if os.name != "nt":
        planted.chmod(0o666)

    proc = _run_harness(tmp_path, planted, "OUR LINE")

    text = planted.read_text(encoding="utf-8")
    assert "OUR LINE" not in text or (
        _mode(planted) == OWNER_ONLY if os.name != "nt" else "True" in _acl(planted)
    ), f"appended to a permissive file: {text!r}"
    if "OUR LINE" not in text:
        assert "DISABLED=True" in proc.stdout, proc.stdout + proc.stderr
        assert text == "planted content\n", f"an untrusted file was mutated: {text!r}"


# ---------------------------------------------------------------------------
# 3. a pre-existing SYMLINK / reparse point
# ---------------------------------------------------------------------------


@requires_pwsh
def test_a_planted_symlink_is_neither_followed_nor_deleted(tmp_path):
    target = tmp_path / "victim.txt"
    target.write_text("victim content\n", encoding="utf-8")
    link = tmp_path / "planted-link.log"
    try:
        os.symlink(target, link)
    except OSError as exc:  # Windows: needs SeCreateSymbolicLinkPrivilege
        pytest.skip(f"cannot create a symlink on this host: {exc}")

    proc = _run_harness(tmp_path, link, "OUR LINE")

    assert link.is_symlink(), "the planted link was unlinked instead of rejected"
    assert target.read_text(encoding="utf-8") == "victim content\n", "the link was followed"
    assert "DISABLED=True" in proc.stdout, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# 4. securing fails -> the launcher still runs, the unsafe entry is untouched
# ---------------------------------------------------------------------------


@requires_pwsh
def test_a_directory_at_the_log_path_disables_logging_not_the_launcher(tmp_path):
    blocked = tmp_path / "blocked.log"
    blocked.mkdir()
    (blocked / "keep.txt").write_text("keep\n", encoding="utf-8")

    proc = _run_harness(tmp_path, blocked, "OUR LINE")

    assert "DISABLED=True" in proc.stdout, proc.stdout + proc.stderr
    assert blocked.is_dir(), "a directory at the log path was removed"
    assert (blocked / "keep.txt").read_text(encoding="utf-8") == "keep\n"


@requires_pwsh
def test_the_launcher_still_runs_and_prints_when_no_log_can_be_secured(tmp_path):
    """An unsecurable log location must cost logging, not the launcher."""
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("pre-existing\n", encoding="utf-8")

    proc = _launch(["--help"], blocker)

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "MegaBasterd-CLI" in proc.stdout, proc.stdout
    assert blocker.read_text(encoding="utf-8") == "pre-existing\n", "the blocker was mutated"
    warnings = [ln for ln in proc.stderr.splitlines() if "file logging disabled" in ln.lower()]
    assert len(warnings) == 1, f"expected exactly one warning, got {warnings!r}"


# ---------------------------------------------------------------------------
# 5. sentinels never reach an artifact or the warning
# ---------------------------------------------------------------------------


@requires_pwsh
def test_no_sentinel_survives_a_run_whose_logging_failed(tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("pre-existing\n", encoding="utf-8")

    proc = _launch(
        [
            "config",
            "set",
            "elc_accounts",
            f'{{"h":{{"user":"u","api_key":"{MEGA_KEY}"}}}}',
            "--password",
            SECRET,
        ],
        blocker,
    )

    assert SECRET not in proc.stderr and MEGA_KEY not in proc.stderr, proc.stderr
    assert blocker.read_text(encoding="utf-8") == "pre-existing\n"


@requires_pwsh
def test_no_sentinel_survives_a_normal_run(tmp_path):
    log_dir = tmp_path / f"logs-{uuid.uuid4().hex[:8]}"
    log_dir.mkdir()

    _launch(["config", "get", "download_path", "--password", SECRET], log_dir)
    _launch(["download", f"https://mega.nz/file/ABCDEFGH#{MEGA_KEY}"], log_dir)

    produced = _artifacts(log_dir)
    assert produced, "no artifacts were produced - this scan would prove nothing"
    for path in produced:
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert SECRET not in text, path.name
        assert MEGA_KEY not in text, path.name


# ---------------------------------------------------------------------------
# 6. structural
# ---------------------------------------------------------------------------


def test_start_transcript_stays_absent():
    assert "Start-Transcript" not in RUN_TEXT.replace("# Deliberately NO Start-Transcript", "")


def test_an_untrusted_entry_is_never_unlinked():
    """The forbidden shape: unlink-and-replace of a path we do not own."""
    body = _code_of("New-SecureLogFile")
    assert "Remove-Item" not in body, "an untrusted pre-existing entry is being deleted"


def test_the_writer_cannot_append_without_securing_first():
    body = _code_of("Write-SecureLogLine")
    assert "New-SecureLogFile" in body
    assert body.index("New-SecureLogFile") < body.index(
        "Add-Content"
    ), "the append must be reachable only after securing succeeded"
    assert "LauncherFileLoggingDisabled" in body, "a failure must disable logging for the run"


def test_exactly_one_launcher_remains():
    assert [p.name for p in REPO.glob("*.ps1")] == ["Run.ps1"]
