"""Integration tests proving Run.ps1 keeps stream tokens out of its logs.

These run the real launcher through PowerShell with an isolated, test-only log
directory (MEGABASTERD_LAUNCHER_LOG_DIR) and a CLI command that exits before any
network access (``--help``). They verify that a ``--token`` value passed on the
launcher command line never appears in the launcher log, the PowerShell
transcript, the CLI log, or captured stdout/stderr, in both the split
(``--token value``) and inline (``--token=value``) forms.

If no PowerShell is available the launcher integration is skipped (the
Python-side argv redaction is covered by tests/test_cli_argv_redaction.py).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUN_PS1 = ROOT / "Run.ps1"

SPLIT_MARKER = "LAUNCHER_TOKEN_SPLIT_FORM_SHOULD_NOT_LEAK"
INLINE_MARKER = "LAUNCHER_TOKEN_INLINE_FORM_SHOULD_NOT_LEAK"


def _powershell() -> str | None:
    return shutil.which("pwsh") or shutil.which("powershell")


pwsh = _powershell()
pytestmark = pytest.mark.skipif(
    pwsh is None, reason="PowerShell (pwsh/powershell) is not available on this host"
)


def _run_launcher(tmp_path: Path, token_args: list[str]) -> tuple[str, dict[str, str]]:
    """Run Run.ps1 with isolated logs; return (combined_stdout_stderr, log_texts)."""
    log_dir = tmp_path / "launcher-logs"
    log_dir.mkdir()
    env = dict(os.environ)
    env["MEGABASTERD_LAUNCHER_LOG_DIR"] = str(log_dir)
    env["NO_COLOR"] = "1"
    env["MEGABASTERD_NO_PAUSE"] = "1"
    env["MEGABASTERD_AUTO_INSTALL"] = "0"
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    # `--help` makes the dispatched CLI exit before any network access while the
    # launcher still logs the (redacted) argument list. A non-MEGA positional
    # and `--port` exercise "unrelated args stay visible / are not consumed".
    cmd = [
        pwsh,
        "-NoProfile",
        "-File",
        str(RUN_PS1),
        "stream",
        "FAKE_NOURL",
        *token_args,
        "--port",
        "8123",
        "--help",
    ]
    proc = subprocess.run(
        cmd,
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        stdin=subprocess.DEVNULL,
    )
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    logs = {p.name: p.read_text(encoding="utf-8", errors="replace") for p in log_dir.glob("*")}
    return combined, logs


def _dispatch_line(logs: dict[str, str]) -> str | None:
    for name, text in logs.items():
        if name.startswith("launcher-") and "transcript" not in name:
            for line in text.splitlines():
                if "Dispatching CLI args:" in line:
                    return line
    return None


@pytest.mark.parametrize(
    "form,marker,token_args",
    [
        ("split", SPLIT_MARKER, ["--token", SPLIT_MARKER]),
        ("inline", INLINE_MARKER, [f"--token={INLINE_MARKER}"]),
    ],
)
def test_launcher_does_not_leak_stream_token(tmp_path, form, marker, token_args):
    combined, logs = _run_launcher(tmp_path, token_args)

    # Primary security assertion: the token value never appears anywhere the
    # launcher wrote, nor in captured stdout/stderr.
    assert marker not in combined, "token leaked into launcher stdout/stderr"
    for name, text in logs.items():
        assert marker not in text, f"token leaked into {name}"

    # Prove the launcher actually dispatched and that redaction ran (not just
    # that the token happened to be absent because nothing was logged).
    dispatch = _dispatch_line(logs)
    if dispatch is None:
        pytest.skip(
            "launcher did not dispatch a CLI command in this environment "
            "(no usable Python/deps); token absence still verified above"
        )

    # The option name stays; the value is replaced with the redaction marker.
    assert "--token" in dispatch
    assert "<redacted>" in dispatch
    # Unrelated, non-sensitive arguments remain visible and are not consumed by
    # the redaction of the token value.
    assert "--port" in dispatch
    assert "8123" in dispatch
    assert "FAKE_NOURL" in dispatch


# `test_launcher_transcript_present_and_clean` used to sit here. Start-Transcript
# was removed from Run.ps1, so no file with "transcript" in its name can exist on
# any host - the test ran the launcher twice, ~12s per matrix cell, and then
# skipped unconditionally. Its invariant is now asserted for free and more
# strictly by test_launcher_no_raw_transcript.py, which greps the shipped source
# for Start-Transcript instead of hoping to observe its output.


def test_launcher_token_redacted_even_when_command_fails(tmp_path):
    """A failing child command must not expose the token in launcher logs."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    env = dict(os.environ)
    env["MEGABASTERD_LAUNCHER_LOG_DIR"] = str(log_dir)
    env["NO_COLOR"] = "1"
    env["MEGABASTERD_NO_PAUSE"] = "1"
    env["MEGABASTERD_AUTO_INSTALL"] = "0"
    cmd = [
        pwsh,
        "-NoProfile",
        "-File",
        str(RUN_PS1),
        "stream",
        "FAKE_NOURL",
        "--token",
        SPLIT_MARKER,
        "--definitely-not-a-real-flag",
    ]
    proc = subprocess.run(
        cmd,
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        stdin=subprocess.DEVNULL,
    )
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    assert SPLIT_MARKER not in combined
    for p in log_dir.glob("*"):
        assert SPLIT_MARKER not in p.read_text(encoding="utf-8", errors="replace")
