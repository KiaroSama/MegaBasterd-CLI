"""The Windows log is owner-only inside the create call, not shortly after it.

Two things the managed API cannot express drove this down to native code.

`FileStream` has no way to attach a security descriptor to the CREATE, so a new
log existed with the parent directory's inherited DACL for the window between
`CreateNew` and `Set-Acl` - short, but long enough for anyone the parent trusts
to open it. And `FileStream` cannot open a reparse point *itself*, so a planted
symlink had to be spotted by a separate `Get-Item` on the name: a different
lookup from the one that opened the file, which is the shape every TOCTOU in
this file has had.

`SecureLogNative` passes the descriptor to `CreateFileW` at `CREATE_NEW`, opens
pre-existing entries with `FILE_FLAG_OPEN_REPARSE_POINT`, and reads attributes,
owner, DACL and file identity from the handle it just opened. These tests drive
the C# lifted verbatim out of Run.ps1, so what runs here is the shipped source.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from tests.launcher_helpers import RUN_TEXT, SECURE_LOG_SOURCE

pwsh = shutil.which("pwsh") or shutil.which("powershell")
requires_pwsh = pytest.mark.skipif(pwsh is None, reason="PowerShell is not available")
windows_only = pytest.mark.skipif(os.name != "nt", reason="the native helper is Windows-only")

LOCAL_SERVICE = "S-1-5-19"


def _source() -> str:
    """The shipped C#, as the here-string these harness snippets compile."""
    return "$script:SecureLogSource = @'\n" + SECURE_LOG_SOURCE + "\n'@"


def _run(tmp_path: Path, body: str, *args: str) -> subprocess.CompletedProcess:
    """Compile the shipped C# and run `body` against it."""
    script = tmp_path / f"native-{uuid.uuid4().hex[:6]}.ps1"
    script.write_text(
        "param([string] $A, [string] $B)\n"
        "$ErrorActionPreference = 'Stop'\n" + _source() + "\n"
        "Add-Type -TypeDefinition $script:SecureLogSource -Language CSharp\n" + body,
        encoding="utf-8",
    )
    return subprocess.run(
        [pwsh, "-NoProfile", "-File", str(script), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
    )


OPEN_ONCE = """
try {
    $r = [MegaBasterd.SecureLogNative]::Open($A)
    "CREATED=$($r.Created)"
    "IDENTITY=$($r.VolumeSerial):$($r.FileIndex)"
    $r.Handle.Dispose()
    "RESULT=opened"
} catch {
    "RESULT=refused"
    "REASON=$($_.Exception.Message)"
}
"""


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


def _acl_of(path: Path) -> str:
    probe = subprocess.run(
        [
            pwsh,
            "-NoProfile",
            "-Command",
            f"$a = Get-Acl -LiteralPath '{path}'; "
            "$t = [System.Security.Principal.SecurityIdentifier]; "
            '"OWNER=$($a.GetOwner($t).Value)"; '
            '"PROTECTED=$($a.AreAccessRulesProtected)"; '
            '"ACES=$(($a.GetAccessRules($true,$true,$t) | ForEach-Object '
            '{ "$($_.AccessControlType):$($_.IdentityReference.Value)" }) -join \',\')"',
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return probe.stdout


# ---------------------------------------------------------------------------
# creation is owner-only inside the create call
# ---------------------------------------------------------------------------


@windows_only
@requires_pwsh
def test_a_created_log_never_inherits_the_parent_directory_grant(tmp_path):
    """The parent hands every child an ACE for a second principal. The log has none.

    This is the window the native create closes: with `Set-Acl` afterwards, the
    file existed with this inherited ACE first, and only stopped being readable
    once the second call landed.
    """
    parent = tmp_path / "inheriting"
    parent.mkdir()
    subprocess.run(
        ["icacls", str(parent), "/grant", f"*{LOCAL_SERVICE}:(OI)(CI)(F)"],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    target = parent / "run.log"

    out = _run(tmp_path, OPEN_ONCE, str(target)).stdout
    assert "RESULT=opened" in out, out
    assert "CREATED=True" in out, out

    rendered = _acl_of(target)
    assert "PROTECTED=True" in rendered, rendered
    assert f"OWNER={_my_sid()}" in rendered, rendered
    assert LOCAL_SERVICE not in rendered, f"the inherited grant survived: {rendered!r}"
    aces = [a for a in rendered.split("ACES=")[1].strip().split(",") if a]
    assert aces == [f"Allow:{_my_sid()}"], aces


def test_the_windows_branch_creates_with_a_descriptor_and_never_calls_set_acl():
    """Structural: no post-create hardening step may come back."""
    source = _source()
    assert "SECURITY_ATTRIBUTES" in source and "CREATE_NEW" in source
    assert "ConvertStringSecurityDescriptorToSecurityDescriptorW" in source
    # D:P is the protected-DACL flag; FA is file-all-access for one SID.
    assert '"O:" + sid + "G:" + sid + "D:P(A;;FA;;;" + sid + ")"' in source
    start = RUN_TEXT.index("function Open-VerifiedLogStream")
    end = RUN_TEXT.index("function Write-SecureLogLine")
    branch = RUN_TEXT[start:end].split("# POSIX, unchanged")[0]
    # Comments stripped: the prose above this function names Set-Acl and Get-Acl
    # to explain why they are gone, and prose must not be able to fail - or pass -
    # a structural assertion.
    code = "\n".join(line for line in branch.splitlines() if not line.lstrip().startswith("#"))
    for forbidden in ("Set-Acl", "Get-Acl", "Add-Content", "Set-Content", "Out-File"):
        assert forbidden not in code, f"{forbidden} is back in the Windows writer"


def test_the_native_open_refuses_delete_sharing_and_follows_no_reparse_point():
    source = _source()
    assert "FILE_FLAG_OPEN_REPARSE_POINT" in source, "a planted link would be followed"
    assert "FILE_SHARE_READ | FILE_SHARE_WRITE" in source
    assert "FILE_SHARE_DELETE" not in source, "delete sharing unpins the name"
    # Every decision comes from the handle, not from a second lookup by name.
    for api in ("GetFileInformationByHandleEx", "GetSecurityInfo", "GetFileInformationByHandle"):
        assert api in source, f"{api} is missing - a check would have to use the path"


# ---------------------------------------------------------------------------
# reparse points
# ---------------------------------------------------------------------------


@windows_only
@requires_pwsh
def test_a_planted_reparse_point_is_refused_and_its_victim_untouched(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("victim content\n", encoding="utf-8")
    link = tmp_path / "planted.log"
    try:
        os.symlink(victim, link)
    except OSError as exc:  # needs SeCreateSymbolicLinkPrivilege
        pytest.skip(f"cannot create a symlink on this host: {exc}")

    out = _run(tmp_path, OPEN_ONCE, str(link)).stdout

    assert "RESULT=refused" in out, out
    assert victim.read_text(encoding="utf-8") == "victim content\n", "the link was followed"
    assert link.is_symlink(), "the planted link was removed instead of refused"


@windows_only
@requires_pwsh
def test_a_regular_file_is_accepted_where_a_reparse_point_is_refused(tmp_path):
    """The control for the test above: same call, safe object, opposite verdict.

    Without it a broken helper that refused everything would look correct.
    """
    target = tmp_path / "plain.log"

    out = _run(tmp_path, OPEN_ONCE, str(target)).stdout

    assert "RESULT=opened" in out, out
    assert "CREATED=True" in out, out


# ---------------------------------------------------------------------------
# handle identity
# ---------------------------------------------------------------------------


IDENTITY_TWICE = """
$first = [MegaBasterd.SecureLogNative]::Open($A)
"FIRST=$($first.VolumeSerial):$($first.FileIndex)"
$stream = New-Object System.IO.FileStream($first.Handle, [System.IO.FileAccess]::Write)
[void]$stream.Seek(0, [System.IO.SeekOrigin]::End)
$w = New-Object System.IO.StreamWriter($stream, (New-Object System.Text.UTF8Encoding($false)))
$w.WriteLine("LINE-ONE"); $w.Flush(); $w.Dispose()
$second = [MegaBasterd.SecureLogNative]::Open($A)
"SECOND=$($second.VolumeSerial):$($second.FileIndex)"
"REOPENED_CREATED=$($second.Created)"
$second.Handle.Dispose()
"""


@windows_only
@requires_pwsh
def test_the_verified_handle_is_the_handle_that_gets_written(tmp_path):
    """Identity is volume serial + file index, taken from the handle itself.

    It is returned for exactly this proof and nothing consults it to authorize
    anything - a path-keyed cache is what caused the original TOCTOU.
    """
    target = tmp_path / "run.log"

    out = _run(tmp_path, IDENTITY_TWICE, str(target)).stdout
    values = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)

    assert values["FIRST"] == values["SECOND"], out
    assert values["REOPENED_CREATED"] == "False", out
    assert target.read_text(encoding="utf-8").strip() == "LINE-ONE"


# ---------------------------------------------------------------------------
# two creators, one file
# ---------------------------------------------------------------------------


COLLIDE = """
$results = @()
1..2 | ForEach-Object {
    try {
        $r = [MegaBasterd.SecureLogNative]::Open($A)
        $results += "created=$($r.Created)"
        $r.Handle.Dispose()
    } catch {
        $results += "refused"
    }
}
$results -join ' '
"""


@windows_only
@requires_pwsh
def test_only_the_first_creator_creates_and_the_second_verifies(tmp_path):
    target = tmp_path / "run.log"

    out = _run(tmp_path, COLLIDE, str(target)).stdout.strip()

    assert "created=True created=False" in out, out
    assert not list(tmp_path.glob("*.tmp")), "a temp artifact was left behind"
    rendered = _acl_of(target)
    assert "PROTECTED=True" in rendered and f"OWNER={_my_sid()}" in rendered, rendered


# ---------------------------------------------------------------------------
# a created file is verified too
# ---------------------------------------------------------------------------


def test_verification_runs_for_created_and_pre_existing_alike():
    """A successful CREATE_NEW says the call was accepted, not that it took.

    The descriptor is handed to CreateFileW, but a volume without ACL support
    drops it silently - so the read-back has to happen on both paths, not only
    when the file was already there.
    """
    source = _source()
    body = source[source.index("public static SecureLogOpen Open(") :]
    body = body[: body.index("static void VerifyKind")]
    code = "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("//"))
    assert "VerifySecurity(handle, sid);" in code, "the read-back is gone"
    guarded = re.search(r"if\s*\(\s*!created\s*\)\s*\{[^}]*VerifySecurity", code, re.S)
    assert not guarded, "VerifySecurity is skipped for newly created files again"


CREATE_THEN_REFUSE = """
[MegaBasterd.SecureLogNative]::CreationSddlOverride = $B
try {
    $r = [MegaBasterd.SecureLogNative]::Open($A)
    $r.Handle.Dispose()
    "RESULT=opened"
} catch {
    "RESULT=refused"
    "REASON=$($_.Exception.Message)"
}
"EXISTS=$(Test-Path -LiteralPath $A)"
"SIZE=$(if (Test-Path -LiteralPath $A) { (Get-Item -LiteralPath $A).Length } else { -1 })"
"""


@windows_only
@requires_pwsh
def test_a_created_file_whose_descriptor_did_not_take_is_refused(tmp_path):
    """Deterministic stand-in for "the volume ignored the descriptor".

    The override makes CreateFileW apply a descriptor that also grants a second
    principal - which it accepts happily - so the only thing that can reject the
    file is the post-create read-back this test exists to prove runs.
    """
    target = tmp_path / "created.log"
    me = _my_sid()
    bad = f"O:{me}G:{me}D:P(A;;FA;;;{me})(A;;FR;;;{LOCAL_SERVICE})"

    out = _run(tmp_path, CREATE_THEN_REFUSE, str(target), bad).stdout

    assert "RESULT=refused" in out, out
    assert "foreign-allow-ace" in out, out
    # It was created - that is the point - but not one byte was written to it.
    assert "EXISTS=True" in out, out
    assert "SIZE=0" in out, out


@windows_only
@requires_pwsh
def test_the_launcher_survives_a_created_file_that_fails_verification(tmp_path):
    """Zero bytes, one fixed warning, console still alive."""
    target = tmp_path / "run.log"
    me = _my_sid()
    bad = f"O:{me}G:{me}D:P(A;;FA;;;{me})(A;;FR;;;{LOCAL_SERVICE})"
    body = (
        f"[MegaBasterd.SecureLogNative]::CreationSddlOverride = '{bad}'\n"
        "$script:LauncherFileLoggingDisabled = $false\n"
        "try {\n"
        "    $r = [MegaBasterd.SecureLogNative]::Open($A)\n"
        "    $r.Handle.Dispose()\n"
        '    "RESULT=opened"\n'
        "} catch {\n"
        '    [Console]::Error.WriteLine("launcher: file logging disabled - '
        'secure log operation failed")\n'
        '    "RESULT=refused"\n'
        "}\n"
        '"STILL_ALIVE=yes"\n'
    )

    proc = _run(tmp_path, body, str(target))

    assert "RESULT=refused" in proc.stdout, proc.stdout + proc.stderr
    assert "STILL_ALIVE=yes" in proc.stdout, "execution stopped instead of degrading"
    warnings = [ln for ln in proc.stderr.splitlines() if "file logging disabled" in ln.lower()]
    assert len(warnings) == 1, f"expected exactly one warning, got {warnings!r}"
    assert target.read_bytes() == b"", "bytes reached a file that failed verification"
    for leak in (str(target), target.name, str(tmp_path)):
        assert leak not in proc.stderr, f"{leak!r} leaked into stderr"
