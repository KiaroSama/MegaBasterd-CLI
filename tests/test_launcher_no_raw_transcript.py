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

REPO = Path(__file__).resolve().parents[1]
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


def _artifacts(log_dir: Path) -> list[Path]:
    return [p for p in log_dir.rglob("*") if p.is_file()]


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


@requires_pwsh
def test_a_password_option_never_reaches_an_artifact(tmp_path):
    log_dir = tmp_path / f"logs-{uuid.uuid4().hex[:8]}"
    log_dir.mkdir()

    _launch(["config", "get", "download_path", "--password", SECRET], log_dir)

    produced = _artifacts(log_dir)
    assert produced, "no artifacts were produced - this scan would prove nothing"
    assert _scan(log_dir) == [], f"secret leaked into {_scan(log_dir)}"


@requires_pwsh
def test_the_launcher_log_is_owner_only_from_creation(tmp_path):
    """Not chmod'd afterwards: there must be no readable window at all."""
    if os.name != "nt":
        pytest.skip("ACL check is Windows-specific")

    log_dir = tmp_path / f"logs-{uuid.uuid4().hex[:8]}"
    log_dir.mkdir()
    _launch(["--help"], log_dir)

    logs = list(log_dir.glob("launcher-*.log"))
    assert logs, "no launcher log was produced"

    probe = subprocess.run(
        [
            pwsh,
            "-NoProfile",
            "-Command",
            f"(Get-Acl -LiteralPath '{logs[0]}').AreAccessRulesProtected",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert probe.stdout.strip() == "True", f"log inherits ACLs: {probe.stdout!r}"
