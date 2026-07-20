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
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RUN_PS1 = REPO / "Run.ps1"
RUN_TEXT = RUN_PS1.read_text(encoding="utf-8")
# The native secure-open helper moved out of Run.ps1 so the launcher would
# stop carrying 350 lines of C#. Tests compile the SHIPPED file, not a copy.
SECURE_LOG_CS = REPO / "launcher" / "SecureLog.cs"
SECURE_LOG_SOURCE = SECURE_LOG_CS.read_text(encoding="utf-8")

pwsh = shutil.which("pwsh") or shutil.which("powershell")
requires_pwsh = pytest.mark.skipif(pwsh is None, reason="PowerShell is not available")
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
