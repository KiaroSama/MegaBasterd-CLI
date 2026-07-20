"""Shared scaffolding for the launcher test modules.

Seven `test_launcher_*` files each re-declared the same PowerShell discovery,
the same skip markers and the same small helpers. Byte-identical copies are
worse than they look: `_extract_function` lifts real code out of Run.ps1, so a
change to the extraction rule had to be made in two places or one file would
quietly start testing something else.

Only the pieces that were IDENTICAL across their copies live here. `_acl` and
`_launch` differ between modules (different probe output, different
encoding/errors handling) and stay where they are rather than being merged into
a helper with a flag for each caller.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RUN_PS1 = REPO / "Run.ps1"
RUN_TEXT = RUN_PS1.read_text(encoding="utf-8")
# The native secure-open helper moved out of Run.ps1 so the launcher would
# stop carrying 350 lines of C#. Tests compile the SHIPPED file, not a copy.
SECURE_LOG_CS = REPO / "launcher" / "SecureLog.cs"
SECURE_LOG_SOURCE = SECURE_LOG_CS.read_text(encoding="utf-8")


def _powershell_hosts() -> dict[str, str]:
    """Every PowerShell host on this machine, by name.

    Windows PowerShell 5.1 and pwsh 7 disagree about what a native command's
    redirected stderr means under ``$ErrorActionPreference = "Stop"`` - 5.1
    turns it into a terminating error, pwsh leaves it as data. Anything that
    runs a child process has to be exercised on both, not on whichever one
    ``which`` happened to find first.
    """
    found = {}
    for name in ("pwsh", "powershell"):
        path = shutil.which(name)
        if path is not None:
            found[name] = path
    return found


POWERSHELL_HOSTS = _powershell_hosts()
# Unchanged default: pwsh when present, Windows PowerShell otherwise. Every
# pre-existing test keeps running on exactly the host it ran on before.
pwsh = POWERSHELL_HOSTS.get("pwsh") or POWERSHELL_HOSTS.get("powershell")
requires_pwsh = pytest.mark.skipif(pwsh is None, reason="PowerShell is not available")

# Fans one test out over every host present. Pair it with @requires_pwsh so a
# machine with no PowerShell reports a skip instead of the test disappearing.
every_powershell_host = pytest.mark.parametrize(
    "ps_host",
    list(POWERSHELL_HOSTS.values()) or [None],
    ids=list(POWERSHELL_HOSTS) or ["no-powershell"],
)


def run_powershell(ps_host: str, script: Path, timeout: int = 120) -> subprocess.CompletedProcess:
    """Run a .ps1 under one specific host.

    ``-ExecutionPolicy Bypass`` is for Windows PowerShell 5.1, which refuses
    ``-File`` under the default machine policy. pwsh accepts and ignores it.
    """
    return subprocess.run(
        [ps_host, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        capture_output=True,
        text=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )


posix_only = pytest.mark.skipif(
    os.name == "nt", reason="POSIX file modes are not a Windows concept"
)
windows_only = pytest.mark.skipif(os.name != "nt", reason="ACL check is Windows-specific")

OWNER_ONLY = 0o600


def artifacts(log_dir: Path) -> list[Path]:
    """Every file the launcher left behind, at any depth."""
    return [p for p in log_dir.rglob("*") if p.is_file()]


def mode(path: Path) -> int:
    """POSIX permission bits, via lstat so a symlink is not followed."""
    return stat.S_IMODE(path.lstat().st_mode)


def my_sid() -> str:
    """The current user's SID, the way the launcher's own verifier reads it."""
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


def extract_function(name: str) -> str:
    """Pull one PowerShell function out of Run.ps1 by brace matching.

    The tests drive the shipped code rather than a copy of it, so this has to
    stay exact - which is the reason it is defined once.
    """
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
