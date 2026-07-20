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
import subprocess
import uuid
from pathlib import Path

import pytest

from tests.launcher_helpers import artifacts as _artifacts
from tests.launcher_helpers import extract_function as _extract_function
from tests.launcher_helpers import mode as _mode

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


def _code_of(name: str) -> str:
    """The function with comment lines dropped, so prose cannot satisfy an assertion."""
    return "\n".join(
        line for line in _extract_function(name).splitlines() if not line.lstrip().startswith("#")
    )


def _script_var(name: str) -> str:
    """Lift a `$script:` assignment out of Run.ps1 verbatim.

    Copying the value into the harness instead let `$script:BroadSids` go
    undefined here: `Test-OwnerOnlyLogFile` threw, its `catch` turned that into
    `return $false`, and every fail-closed test passed without ever exercising a
    verification that could succeed.
    """
    for line in RUN_TEXT.splitlines():
        if line.startswith(f"$script:{name} ="):
            return line
    raise AssertionError(f"$script:{name} is no longer defined in Run.ps1")


HARNESS_PRELUDE = """param([string] $Target, [string] $Line = 'harness line')
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:IsWindowsHost = ([System.Environment]::OSVersion.Platform -eq "Win32NT")
$script:UnixOwnerOnly = if ($script:IsWindowsHost) { $null } else {
    [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
}
$script:LauncherFileLoggingDisabled = $false
$LogDir = Split-Path -Parent $Target
"""
HARNESS_PRELUDE += _script_var("LogFailureReason") + "\n"

HARNESS_FUNCTIONS = (
    "Get-RedactedText",
    "Disable-LauncherFileLogging",
    "Get-CurrentUserSid",
    "Test-OwnerOnlyLogFile",
    "Open-VerifiedLogStream",
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


TWO_LINE_PRELUDE = """param(
    [string] $Target,
    [string] $Line1 = 'first line',
    [string] $Line2 = 'second line',
    [string] $Mutate = ''
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:IsWindowsHost = ([System.Environment]::OSVersion.Platform -eq "Win32NT")
$script:UnixOwnerOnly = if ($script:IsWindowsHost) { $null } else {
    [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
}
$script:LauncherFileLoggingDisabled = $false
$LogDir = Split-Path -Parent $Target
"""
TWO_LINE_PRELUDE += _script_var("LogFailureReason") + "\n"


def _write_two_line_harness(tmp_path: Path) -> Path:
    """Write, let the caller swap the file, write again.

    A single-write harness cannot see this bug at all: the path cache was only
    consulted from the *second* call onwards, so the defect lived entirely in
    the gap between two writes to the same path.
    """
    body = TWO_LINE_PRELUDE + "\n".join(_extract_function(n) for n in HARNESS_FUNCTIONS)
    # The ACL dump is not decoration. When this failed on a CI runner and passed
    # on the dev machine, the fixed warning text ("secure log operation failed")
    # correctly told us nothing, and the difference had to be guessed at. Now a
    # failure carries the owner and ACEs that actually caused it.
    body += """
Write-SecureLogLine $Target $Line1
"AFTER_FIRST=$($script:LauncherFileLoggingDisabled)"
if ($script:IsWindowsHost -and (Test-Path -LiteralPath $Target)) {
    # Windows-guarded: Get-Acl and WindowsIdentity do not exist in pwsh on
    # Linux, and with $ErrorActionPreference='Stop' an unguarded call kills the
    # harness before the mutation step - which reads as "the planted link was
    # unlinked" rather than as the diagnostic itself being broken.
    $probe = Get-Acl -LiteralPath $Target
    $sidType = [System.Security.Principal.SecurityIdentifier]
    "OWNER=$($probe.GetOwner($sidType).Value)"
    "ME=$((Get-CurrentUserSid).Value)"
    "PROTECTED=$($probe.AreAccessRulesProtected)"
    "ACES=$(($probe.GetAccessRules($true,$true,$sidType) | ForEach-Object {
        "$($_.AccessControlType):$($_.IdentityReference.Value):$($_.FileSystemRights)" }) -join ' | ')"
}
if ($Mutate) { & $Mutate $Target }
Write-SecureLogLine $Target $Line2
"AFTER_SECOND=$($script:LauncherFileLoggingDisabled)"
"STILL_ALIVE=yes"
"""
    script = tmp_path / "two-line-harness.ps1"
    script.write_text(body, encoding="utf-8")
    return script


def _run_two_line(tmp_path: Path, target: Path, mutate: Path | None = None, **kw):
    args = [
        pwsh,
        "-NoProfile",
        "-File",
        str(_write_two_line_harness(tmp_path)),
        str(target),
        kw.get("line1", "FIRST-LINE"),
        kw.get("line2", "SECOND-LINE"),
        str(mutate) if mutate else "",
    ]
    return subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180
    )


def _mutation_script(tmp_path: Path, body: str, name: str = "mutate.ps1") -> Path:
    script = tmp_path / name
    script.write_text("param([string] $Target)\n$ErrorActionPreference='Stop'\n" + body, "utf-8")
    return script


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
# 6. a decision about a pathname must not authorize a later object
# ---------------------------------------------------------------------------


@windows_only
@requires_pwsh
def test_a_normal_second_write_appends_to_the_same_owner_only_file(tmp_path):
    """The control. Without this, every assertion below passes by writing nothing."""
    target = tmp_path / "run.log"

    proc = _run_two_line(tmp_path, target)

    assert "AFTER_SECOND=False" in proc.stdout, proc.stdout + proc.stderr
    text = target.read_text(encoding="utf-8")
    assert "FIRST-LINE" in text and "SECOND-LINE" in text, text
    rendered = _acl(target)
    assert rendered.splitlines()[:1] == ["True"], f"log inherits ACLs: {rendered!r}"
    for broad in BROAD:
        assert broad not in rendered, f"log grants {broad}: {rendered!r}"
    me = os.environ.get("USERNAME", "")
    assert me and me.lower() in rendered.lower(), f"the owner lost access: {rendered!r}"


@windows_only
@requires_pwsh
def test_a_replacement_carrying_a_broad_ace_is_not_written_to(tmp_path):
    """The defect, exactly: same pathname, different object, after a good write.

    The old code cached `$script:SecuredLogs[$Path] = $true` and then re-entered
    through `Test-Path` alone, so the second `Add-Content` resolved the name
    again and appended into whatever now answered to it.
    """
    target = tmp_path / "run.log"
    mutate = _mutation_script(
        tmp_path,
        # Delete our file and drop a *regular* file with an explicit Everyone
        # read ACE at the same name. SIDs, not names: a localized Windows has no
        # group literally called "Everyone".
        "Remove-Item -LiteralPath $Target -Force\n"
        "Set-Content -LiteralPath $Target -Value 'PLANTED' -NoNewline\n"
        "icacls $Target /inheritance:r /grant '*S-1-1-0:(R)' "
        "/grant ('{0}:(F)' -f [System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
        " | Out-Null\n",
    )

    proc = _run_two_line(tmp_path, target, mutate)

    assert "AFTER_FIRST=False" in proc.stdout, f"the first write failed: {proc.stdout}{proc.stderr}"
    text = target.read_text(encoding="utf-8")
    assert "SECOND-LINE" not in text, f"wrote into a replacement carrying a broad ACE: {text!r}"
    assert text == "PLANTED", f"the planted replacement was mutated: {text!r}"
    assert "AFTER_SECOND=True" in proc.stdout, proc.stdout + proc.stderr
    assert "STILL_ALIVE=yes" in proc.stdout, "the launcher died instead of dropping logging"
    still_broad = _acl(target)
    assert "S-1-1-0" in still_broad or "Everyone" in still_broad, (
        "the planted file's ACL was repaired instead of the file being refused: " f"{still_broad!r}"
    )


@requires_pwsh
def test_a_reparse_point_planted_after_the_first_write_is_not_followed(tmp_path):
    """Replace the name with a link once it is already 'known good'."""
    victim = tmp_path / "victim.txt"
    victim.write_text("victim content\n", encoding="utf-8")
    target = tmp_path / "run.log"
    probe = tmp_path / "linkprobe"
    try:
        os.symlink(victim, probe)
        probe.unlink()
    except OSError as exc:  # Windows: needs SeCreateSymbolicLinkPrivilege
        pytest.skip(f"cannot create a symlink on this host: {exc}")
    mutate = _mutation_script(
        tmp_path,
        "Remove-Item -LiteralPath $Target -Force\n"
        f"New-Item -ItemType SymbolicLink -Path $Target -Target '{victim}' | Out-Null\n",
    )

    proc = _run_two_line(tmp_path, target, mutate)

    assert "AFTER_FIRST=False" in proc.stdout, f"the first write failed: {proc.stdout}{proc.stderr}"
    assert victim.read_text(encoding="utf-8") == "victim content\n", "the link was followed"
    assert Path(target).is_symlink(), "the planted link was unlinked instead of rejected"
    assert "AFTER_SECOND=True" in proc.stdout, proc.stdout + proc.stderr
    assert "STILL_ALIVE=yes" in proc.stdout


@requires_pwsh
def test_a_directory_swapped_in_after_the_first_write_is_rejected(tmp_path):
    """Deterministic and privilege-free: no cache may skip the non-regular check.

    The symlink test above needs a privilege CI hosts often lack. A directory
    reproduces the same bypass with nothing but `mkdir`, so this one always runs.
    """
    target = tmp_path / "run.log"
    mutate = _mutation_script(
        tmp_path,
        "Remove-Item -LiteralPath $Target -Force\n"
        "New-Item -ItemType Directory -Path $Target | Out-Null\n"
        "Set-Content -LiteralPath (Join-Path $Target 'keep.txt') -Value 'keep' -NoNewline\n",
    )

    proc = _run_two_line(tmp_path, target, mutate)

    assert "AFTER_FIRST=False" in proc.stdout, f"the first write failed: {proc.stdout}{proc.stderr}"
    assert Path(target).is_dir(), "the swapped-in directory was removed"
    assert (Path(target) / "keep.txt").read_text(encoding="utf-8") == "keep"
    assert "AFTER_SECOND=True" in proc.stdout, proc.stdout + proc.stderr
    assert "STILL_ALIVE=yes" in proc.stdout


@windows_only
@requires_pwsh
def test_exactly_one_warning_and_no_secret_when_the_second_write_fails(tmp_path):
    """One sanitized line on stderr, and the sentinel is nowhere on disk either."""
    target = tmp_path / f"run-{SECRET}.log"
    mutate = _mutation_script(
        tmp_path,
        "Remove-Item -LiteralPath $Target -Force\n"
        "New-Item -ItemType Directory -Path $Target | Out-Null\n",
    )

    proc = _run_two_line(
        tmp_path,
        target,
        mutate,
        line1=f"first --password {SECRET}",
        line2=f"second --password {SECRET}",
    )

    warnings = [ln for ln in proc.stderr.splitlines() if "file logging disabled" in ln.lower()]
    assert len(warnings) == 1, f"expected exactly one warning, got {warnings!r}"
    assert SECRET not in proc.stderr, proc.stderr
    for produced in tmp_path.rglob("*"):
        if produced.is_file() and produced.suffix != ".ps1":
            body = produced.read_text(encoding="utf-8", errors="ignore")
            assert SECRET not in body, f"{produced.name}: {body!r}"


# ---------------------------------------------------------------------------
# 7. structural
# ---------------------------------------------------------------------------


def test_an_untrusted_entry_is_never_unlinked():
    """The forbidden shape: unlink-and-replace of a path we do not own."""
    body = _code_of("Open-VerifiedLogStream")
    assert "Remove-Item" not in body, "an untrusted pre-existing entry is being deleted"


def test_the_writer_never_appends_by_pathname():
    """`Add-Content` resolves the name again - that is the whole defect."""
    body = _code_of("Write-SecureLogLine")
    assert "Add-Content" not in body, "the line is being appended by pathname, not by handle"
    assert "Open-VerifiedLogStream" in body, "the write must come from the verified stream"
    assert "LauncherFileLoggingDisabled" in body, "a failure must disable logging for the run"


def test_no_pathname_is_cached_as_an_authorization():
    """A boolean keyed on a path authorizes an object that no longer exists."""
    code = [ln for ln in RUN_TEXT.splitlines() if not ln.lstrip().startswith("#")]
    assert not [ln for ln in code if "SecuredLogs" in ln], "the path-keyed cache is back"


def test_the_stream_is_pinned_against_replacement_while_it_is_verified():
    """FileShare.Delete would let the name be renamed away between the two."""
    body = _code_of("Open-VerifiedLogStream")
    assert "[System.IO.FileShare]::ReadWrite" in body, "the share mode must not permit Delete"
    assert "FileShare]::Delete" not in body, "granting Delete unpins the name"
    assert body.index("FileStream]::new") < body.index(
        "Test-OwnerOnlyLogFile"
    ), "the handle must be held before the DACL is trusted"


def test_windows_does_not_depend_on_a_type_absent_from_powershell_5_1():
    """FileStreamOptions is .NET Core only; on 5.1 it threw and killed logging."""
    body = _code_of("Open-VerifiedLogStream")
    windows_branch = body[body.index("if ($script:IsWindowsHost) {") :].split("} else {")[0]
    assert "FileStreamOptions" not in windows_branch, "5.1 cannot construct this"


# ---------------------------------------------------------------------------
# 8. the verifier is a positive allowlist of one principal, not a blacklist
# ---------------------------------------------------------------------------

VERIFIER_FUNCTIONS = ("Get-CurrentUserSid", "Test-OwnerOnlyLogFile")


def _verifier_harness(tmp_path: Path, sid_override: str = "") -> Path:
    """Call the shipped verifier directly and print its verdict.

    `Get-CurrentUserSid` exists so this can drive the owner-mismatch branch:
    changing a file's owner needs SeRestorePrivilege, but pretending to *be*
    another principal needs nothing.
    """
    body = (
        "param([string] $Target)\n"
        "Set-StrictMode -Version 2.0\n"
        "$ErrorActionPreference = 'Stop'\n"
        '$script:IsWindowsHost = ([System.Environment]::OSVersion.Platform -eq "Win32NT")\n'
        "$script:UnixOwnerOnly = $null\n"
    )
    body += "\n".join(_extract_function(n) for n in VERIFIER_FUNCTIONS)
    if sid_override:
        body += (
            "\nfunction Get-CurrentUserSid { return "
            f"[System.Security.Principal.SecurityIdentifier]::new('{sid_override}') }}\n"
        )
    body += '\n"VERDICT=$(Test-OwnerOnlyLogFile $Target)"\n'
    # Same reasoning as the two-line harness: a bare True/False cannot explain a
    # rejection, and a rejection that only happens on a CI runner is exactly the
    # one you cannot step through.
    body += """
if (Test-Path -LiteralPath $Target) {
    $probe = Get-Acl -LiteralPath $Target
    $sidType = [System.Security.Principal.SecurityIdentifier]
    "OWNER=$($probe.GetOwner($sidType).Value)"
    "ME=$((Get-CurrentUserSid).Value)"
    "PROTECTED=$($probe.AreAccessRulesProtected)"
    "ACES=$(($probe.GetAccessRules($true,$true,$sidType) | ForEach-Object {
        "$($_.AccessControlType):$($_.IdentityReference.Value):$($_.FileSystemRights)" }) -join ' | ')"
}
"""
    script = tmp_path / f"verify-{uuid.uuid4().hex[:6]}.ps1"
    script.write_text(body, encoding="utf-8")
    return script


def _verdict(tmp_path: Path, target: Path, sid_override: str = "") -> bool:
    proc = subprocess.run(
        [pwsh, "-NoProfile", "-File", str(_verifier_harness(tmp_path, sid_override)), str(target)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert "VERDICT=" in proc.stdout, proc.stdout + proc.stderr
    global LAST_VERDICT
    LAST_VERDICT = proc.stdout + proc.stderr
    return "VERDICT=True" in proc.stdout


def _my_sid() -> str:
    probe = subprocess.run(
        [
            pwsh,
            "-NoProfile",
            "-Command",
            "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return probe.stdout.strip()


def _set_dacl(target: Path, *aces: str) -> None:
    """Replace the WHOLE DACL with exactly these ACEs, and own the file.

    Each ace is ``SID:Rights:Allow|Deny``.

    Not `icacls /inheritance:r`: that removes only INHERITED entries. When a
    file's parent has no inheritable ACEs, Windows fills the new DACL from the
    process token's DEFAULT DACL instead, and those entries are explicit - so
    they survive `/inheritance:r` untouched. On a CI runner that left the
    "owner alone with FullControl" fixture holding three principals (LOCAL
    SYSTEM, Administrators, us), and the verifier correctly refused it. Nothing
    was wrong with the code under test; the fixture had simply never built the
    state it claimed to.

    A fresh FileSecurity is the same mechanism the launcher itself uses, and it
    replaces the DACL outright, so the fixture is the same on every host.
    """
    rules = "; ".join(
        "$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("
        f"[System.Security.Principal.SecurityIdentifier]::new('{sid}'),"
        f"[System.Security.AccessControl.FileSystemRights]::{rights},"
        f"[System.Security.AccessControl.AccessControlType]::{kind})))"
        for sid, rights, kind in (a.split(":") for a in aces)
    )
    script = (
        "$ErrorActionPreference='Stop'; "
        "$acl = New-Object System.Security.AccessControl.FileSecurity; "
        "$acl.SetAccessRuleProtection($true,$false); "
        "$acl.SetOwner([System.Security.Principal.WindowsIdentity]::GetCurrent().User); "
        f"{rules}; "
        f"Set-Acl -LiteralPath '{target}' -AclObject $acl"
    )
    done = subprocess.run(
        [pwsh, "-NoProfile", "-Command", script],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stdout + done.stderr


LOCAL_SERVICE = "S-1-5-19"  # stable, well-known, and never the current user

# Whatever the last _verdict() call saw, so a rejection can say why.
LAST_VERDICT = ""


@windows_only
@requires_pwsh
def test_a_file_we_own_alone_with_full_control_is_accepted(tmp_path):
    """Positive control. Every rejection below is meaningless without it."""
    target = tmp_path / "ok.log"
    target.write_text("", encoding="utf-8")
    _set_dacl(target, f"{_my_sid()}:FullControl:Allow")

    assert _verdict(tmp_path, target) is True, LAST_VERDICT

    proc = _run_two_line(tmp_path, target)
    assert "AFTER_SECOND=False" in proc.stdout, proc.stdout + proc.stderr
    text = target.read_text(encoding="utf-8")
    assert "FIRST-LINE" in text and "SECOND-LINE" in text, text


@windows_only
@requires_pwsh
def test_an_ace_for_any_other_principal_is_rejected(tmp_path):
    """The blacklist accepted this: LOCAL SERVICE is not one of the six broad SIDs."""
    target = tmp_path / "other.log"
    target.write_text("planted\n", encoding="utf-8")
    _set_dacl(target, f"{_my_sid()}:FullControl:Allow", f"{LOCAL_SERVICE}:Read:Allow")

    assert _verdict(tmp_path, target) is False

    proc = _run_two_line(tmp_path, target)
    assert "AFTER_FIRST=True" in proc.stdout, proc.stdout + proc.stderr
    assert target.read_text(encoding="utf-8") == "planted\n", "an unsafe file was written to"
    rendered = _acl(target)
    assert (
        LOCAL_SERVICE in rendered or "LOCAL SERVICE" in rendered
    ), f"the other principal's ACE was stripped instead of the file refused: {rendered!r}"


@windows_only
@requires_pwsh
def test_read_only_access_for_us_is_not_enough(tmp_path):
    """Being able to read a file is not the same as owning it exclusively."""
    target = tmp_path / "readonly.log"
    target.write_text("planted\n", encoding="utf-8")
    _set_dacl(target, f"{_my_sid()}:Read:Allow")

    assert _verdict(tmp_path, target) is False

    proc = _run_two_line(tmp_path, target)
    assert "AFTER_FIRST=True" in proc.stdout, proc.stdout + proc.stderr
    assert target.read_text(encoding="utf-8") == "planted\n"


@windows_only
@requires_pwsh
def test_a_deny_ace_on_ourselves_is_rejected(tmp_path):
    """Allow ACEs alone do not describe effective rights once a Deny exists."""
    target = tmp_path / "denied.log"
    target.write_text("planted\n", encoding="utf-8")
    _set_dacl(target, f"{_my_sid()}:FullControl:Allow", f"{_my_sid()}:Write:Deny")

    assert _verdict(tmp_path, target) is False


@windows_only
@requires_pwsh
def test_an_owner_that_is_not_the_current_user_is_rejected(tmp_path):
    """Deterministic, and needs no privilege.

    Changing a file's owner requires SeRestorePrivilege, which an ordinary
    account does not hold - so instead the harness reports a different current
    SID. The DACL names only that SID, so every ACE check passes and the owner
    comparison is the only thing left that can reject the file.
    """
    target = tmp_path / "owned.log"
    target.write_text("planted\n", encoding="utf-8")
    _set_dacl(target, f"{LOCAL_SERVICE}:FullControl:Allow")

    assert _verdict(tmp_path, target, sid_override=LOCAL_SERVICE) is False
    # Not read_text: the DACL names only LOCAL SERVICE, so being the owner
    # grants READ_CONTROL but not READ_DATA. What matters is that the rejected
    # file still exists and still carries the ACL it was refused for.
    assert target.exists(), "the rejected file was removed"
    rendered = _acl(target)
    assert LOCAL_SERVICE in rendered or "LOCAL SERVICE" in rendered, rendered
    assert _my_sid() not in rendered, f"the DACL was repaired in our favour: {rendered!r}"


def test_the_verifier_allowlists_the_current_sid_rather_than_blacklisting():
    body = _code_of("Test-OwnerOnlyLogFile")
    assert "Get-CurrentUserSid" in body, "the verifier must resolve the current principal"
    assert "GetOwner" in body, "the file owner must be compared to the current SID"
    assert "FullControl" in body, "the current user's rights must be proven complete"
    assert "BroadSids" not in RUN_TEXT, "the SID blacklist is back"


# ---------------------------------------------------------------------------
# 9. no raw exception text or path ever reaches stderr
# ---------------------------------------------------------------------------

PATH_SENTINEL = "SENTINEL-PW-9921"
MAIL_SENTINEL = "user@example.com"


def _leak_harness(tmp_path: Path, stub: str = "") -> Path:
    body = TWO_LINE_PRELUDE + "\n".join(_extract_function(n) for n in HARNESS_FUNCTIONS)
    if stub:
        body += "\n" + stub + "\n"
    body += (
        "\nWrite-SecureLogLine $Target $Line1\n"
        '"AFTER_FIRST=$($script:LauncherFileLoggingDisabled)"\n'
        "Write-SecureLogLine $Target $Line2\n"
        '"AFTER_SECOND=$($script:LauncherFileLoggingDisabled)"\n'
        '"STILL_ALIVE=yes"\n'
    )
    script = tmp_path / f"leak-{uuid.uuid4().hex[:6]}.ps1"
    script.write_text(body, encoding="utf-8")
    return script


def _run_leak(tmp_path: Path, target: Path, stub: str = ""):
    return subprocess.run(
        [
            pwsh,
            "-NoProfile",
            "-File",
            str(_leak_harness(tmp_path, stub)),
            str(target),
            "A",
            "B",
            "",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
    )


def _assert_nothing_leaked(proc, target: Path, tmp_path: Path) -> None:
    warnings = [ln for ln in proc.stderr.splitlines() if "file logging disabled" in ln.lower()]
    assert len(warnings) == 1, f"expected exactly one warning, got {warnings!r}"
    assert "secure log operation failed" in warnings[0], warnings[0]
    for leak in (PATH_SENTINEL, MAIL_SENTINEL, target.name, str(target), str(tmp_path)):
        assert leak not in proc.stderr, f"{leak!r} leaked into stderr: {proc.stderr!r}"
    assert "STILL_ALIVE=yes" in proc.stdout, "the launcher died instead of dropping logging"
    for produced in tmp_path.rglob("*"):
        if produced.is_file() and produced.suffix != ".ps1":
            body = produced.read_text(encoding="utf-8", errors="ignore")
            assert PATH_SENTINEL not in body and MAIL_SENTINEL not in body, produced.name


def _sentinel_dir(tmp_path: Path) -> Path:
    holder = tmp_path / f"{PATH_SENTINEL}-{MAIL_SENTINEL}"
    holder.mkdir()
    return holder


@windows_only
@requires_pwsh
def test_a_real_sharing_violation_does_not_disclose_the_path(tmp_path):
    """No injected message at all: .NET's own IOException text embeds the path."""
    target = _sentinel_dir(tmp_path) / "run.log"
    target.write_text("", encoding="utf-8")
    _set_dacl(target, f"{_my_sid()}:FullControl:Allow")
    stub = (
        "$blocker = [System.IO.FileStream]::new($Target, "
        "[System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, "
        "[System.IO.FileShare]::None)\n"
    )

    proc = _run_leak(tmp_path, target, stub)

    assert "AFTER_FIRST=True" in proc.stdout, f"the open unexpectedly succeeded: {proc.stdout}"
    _assert_nothing_leaked(proc, target, tmp_path)


@windows_only
@requires_pwsh
def test_an_acl_failure_does_not_disclose_the_path(tmp_path):
    target = _sentinel_dir(tmp_path) / "run.log"
    stub = 'function Get-Acl { throw "Get-Acl blew up on $Target" }\n'

    proc = _run_leak(tmp_path, target, stub)

    assert "AFTER_FIRST=True" in proc.stdout, proc.stdout + proc.stderr
    _assert_nothing_leaked(proc, target, tmp_path)


@windows_only
@requires_pwsh
def test_a_write_failure_does_not_disclose_the_path(tmp_path):
    """A path-bearing IOException raised at the write step, as a full disk gives."""
    target = _sentinel_dir(tmp_path) / "run.log"
    stub = (
        "function Open-VerifiedLogStream { param([string] $Path)\n"
        "    throw [System.IO.IOException]::new("
        '"There is not enough space on the disk. : $Path") }\n'
    )

    proc = _run_leak(tmp_path, target, stub)

    assert "AFTER_FIRST=True" in proc.stdout, proc.stdout + proc.stderr
    _assert_nothing_leaked(proc, target, tmp_path)


def test_the_writer_never_forwards_the_raw_exception():
    body = _code_of("Write-SecureLogLine")
    assert "Exception.Message" not in body, "raw .NET exception text is being forwarded"
    assert "$script:LogFailureReason" in body, "the warning must use the fixed category"


def test_controlled_throw_messages_carry_no_path():
    """Our own refusals must not interpolate $Path either."""
    for name in ("Open-VerifiedLogStream", "Test-OwnerOnlyLogFile"):
        for line in _code_of(name).splitlines():
            if "throw" in line:
                assert "$Path" not in line, f"{name} interpolates the path: {line.strip()!r}"
