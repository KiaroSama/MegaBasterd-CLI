"""The launcher must never write a raw secret, not even briefly.

`Start-Transcript` opens its file with a "Host Application:" header carrying
the full outer command line. The launcher wrote that raw, ran for however long
the command took, and scrubbed the file only at exit - so every secret passed
on the command line sat readable on disk for the whole run, and survived
permanently if the process was Ctrl+C'd, window-closed, or killed. The scrub
also read the entire transcript with `Get-Content -Raw`.

Redacting at exit is the wrong shape regardless of how good the regexes are:
it defends a file that already contains the secret. Redaction now happens
before each line is written, so there is no instant at which a raw secret
exists on disk, and the crash paths need no special handling.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from tests.launcher_helpers import artifacts as _artifacts

REPO = Path(__file__).resolve().parents[1]

# Every test here spawns the real Run.ps1, which may create and install into
# the project .venv. That is one shared resource, so they all run on a single
# xdist worker (--dist loadgroup) rather than racing each other over it.
pytestmark = pytest.mark.xdist_group("launcher_subprocess")
RUN_PS1 = REPO / "Run.ps1"

SECRET = "SENTINEL-PW-8842"
MEGA_KEY = "SENTINELKEY9911"

pwsh = shutil.which("pwsh") or shutil.which("powershell")
requires_pwsh = pytest.mark.skipif(pwsh is None, reason="PowerShell is not available")


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


def _scan(log_dir: Path) -> list[str]:
    leaks = []
    for path in _artifacts(log_dir):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if SECRET in text or MEGA_KEY in text:
            leaks.append(path.name)
    return leaks


# ---------------------------------------------------------------------------
# Structural: the dangerous shape is gone, not merely patched
# ---------------------------------------------------------------------------


def test_the_launcher_starts_no_raw_transcript():
    source = RUN_PS1.read_text(encoding="utf-8")
    assert "Start-Transcript" not in source.replace(
        "# Deliberately NO Start-Transcript", ""
    ), "a raw transcript is being started again"


def test_no_whole_file_scrub_remains():
    """`Get-Content -Raw` was both the memory spike and the wrong-shape fix."""
    source = RUN_PS1.read_text(encoding="utf-8")
    assert "Get-Content -LiteralPath $Path -Raw" not in source
    assert "Protect-TranscriptFile" not in source


def test_exactly_one_launcher_remains():
    """The user's constraint: one entry point at the root, not a script tree."""
    launchers = list(REPO.glob("*.ps1"))
    assert [p.name for p in launchers] == ["Run.ps1"], launchers


# ---------------------------------------------------------------------------
# Behavioural: run it and scan everything it produced
# ---------------------------------------------------------------------------


@requires_pwsh
def test_a_secret_in_a_json_positional_never_reaches_an_artifact(tmp_path):
    """The ELC api_key shape: not an --option, so name-matching missed it."""
    log_dir = tmp_path / f"logs-{uuid.uuid4().hex[:8]}"
    log_dir.mkdir()

    _launch(
        ["config", "set", "elc_accounts", f'{{"h":{{"user":"u","api_key":"{SECRET}"}}}}'],
        log_dir,
    )

    produced = _artifacts(log_dir)
    assert produced, "no artifacts were produced - this scan would prove nothing"
    assert _scan(log_dir) == [], f"secret leaked into {_scan(log_dir)}"
