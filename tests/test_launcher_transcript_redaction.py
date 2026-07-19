"""Launcher redaction rules, now applied at the WRITE instead of at exit.

These tests used to drive ``Protect-TranscriptFile``, which scrubbed a raw
transcript after the fact. That whole design is gone: it left the secret
readable on disk for the length of the run and forever if the process was
killed. The rules it enforced are still exactly right, so they moved with it -
they now execute ``Get-RedactedText``, the single function every launcher log
line passes through before it is written.

The structural invariants that used to guard the scrub ordering are replaced
by a stronger one in test_launcher_no_raw_transcript.py: there is no raw
artifact to order anything against.
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
        + _extract_function("Get-RedactedText")
        + "\n$raw = Get-Content -LiteralPath $Target -Raw\n"
        + "Set-Content -LiteralPath $Target -Value (Get-RedactedText $raw) -NoNewline\n",
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


def test_redaction_stayed_in_powershell():
    """Python may never start, so the launcher needs its own guard."""
    assert "function Get-RedactedText" in RUN_TEXT


def test_every_log_line_passes_through_the_redactor():
    """The invariant that replaces "scrub before the pause prompt".

    Ordering only mattered while a raw file existed. What matters now is that
    nothing reaches disk unredacted - a property of the single writer, not of
    when cleanup happens to run.
    """
    body = _extract_function("Write-RunLog")
    assert "Get-RedactedText $Message" in body, "a log line can bypass redaction"
    assert body.index("Get-RedactedText") < body.index(
        "Add-Content"
    ), "redaction must happen before the write, not after"
