"""The transcript half of launcher redaction must stay in PowerShell.

The interactive menu moved to Python, but ``Start-Transcript`` is a PowerShell
artifact: its "Host Application:" header captures the raw outer command line,
and it has to be scrubbed even when Python never starts. These tests execute
the real ``Protect-TranscriptFile`` out of Run.ps1 against a crafted transcript
and assert the four shapes that were fixed recently still redact, plus the
structural invariants (scrub before the pause prompt, scrub on Ctrl+C).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUN_PS1 = ROOT / "Run.ps1"
RUN_TEXT = RUN_PS1.read_text(encoding="utf-8")

pwsh = shutil.which("pwsh") or shutil.which("powershell")
pytestmark = pytest.mark.skipif(pwsh is None, reason="PowerShell is not available on this host")


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


TRANSCRIPT = """Host Application: pwsh -File Run.ps1 stream L --token TOKENVALUE
Host Application: pwsh -File Run.ps1 stream L --token=INLINETOKEN
-p STARTOFLINEPW
run download -p "quoted secret pw" -o out
config set elc_accounts {"host":{"user":"u","api_key":"ELCAPIKEY"}}
download https://mega.nz/file/ID#SHAREKEY
this line has nothing sensitive at all
"""

SECRETS = [
    "TOKENVALUE",
    "INLINETOKEN",
    "STARTOFLINEPW",
    "quoted secret pw",
    "ELCAPIKEY",
    "SHAREKEY",
]


@pytest.fixture(scope="module")
def scrubbed(tmp_path_factory) -> str:
    target = tmp_path_factory.mktemp("transcript") / "launcher-transcript.log"
    target.write_text(TRANSCRIPT, encoding="utf-8")
    script = tmp_path_factory.mktemp("ps") / "scrub.ps1"
    script.write_text(
        "param([string] $Target)\n"
        "function Write-RunLog { param([string] $Level, [string] $Message) }\n"
        + _extract_function("Protect-TranscriptFile")
        + "\nProtect-TranscriptFile -Path $Target\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [pwsh, "-NoProfile", "-File", str(script), str(target)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return target.read_text(encoding="utf-8")


@pytest.mark.parametrize("secret", SECRETS)
def test_secret_is_scrubbed_from_the_transcript(scrubbed, secret):
    assert secret not in scrubbed


def test_scrub_keeps_the_transcript_readable(scrubbed):
    assert "this line has nothing sensitive at all" in scrubbed
    assert "<redacted>" in scrubbed
    assert "<redacted-link>" in scrubbed
    # The non-secret half of the ELC payload survives, so the log stays useful.
    assert '"user":"u"' in scrubbed


def test_start_of_line_short_password_form_is_covered(scrubbed):
    assert re.search(r"(?m)^-p\s+<redacted>$", scrubbed)


def test_quoted_short_password_value_is_consumed_whole(scrubbed):
    # `\S+` used to stop at the first space, leaving `secret pw"` behind.
    assert re.search(r"-p <redacted> -o out", scrubbed)


# --- structural invariants -------------------------------------------------


def test_transcript_scrub_stayed_in_powershell():
    assert "function Protect-TranscriptFile" in RUN_TEXT
    assert "Protect-TranscriptFile $LauncherTranscriptPath" in RUN_TEXT


def test_scrub_runs_before_the_pause_prompt():
    stop = RUN_TEXT.index("    Stop-LauncherTranscript\n")
    pause = RUN_TEXT.index("Press Enter to close")
    assert stop < pause, "the transcript must be scrubbed before the pause prompt"


def test_engine_exiting_handler_still_scrubs_on_ctrl_c():
    assert "Register-EngineEvent PowerShell.Exiting -Action { Stop-LauncherTranscript }" in RUN_TEXT


def test_stop_is_idempotent_guarded():
    body = _extract_function("Stop-LauncherTranscript")
    assert "if (-not $script:transcriptStarted)" in body
    assert "$script:transcriptStarted = $false" in body
