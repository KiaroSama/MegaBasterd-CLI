"""Regression tests for the launcher's Python probe and its child-stderr handling.

Windows PowerShell 5.1 turns a native command's redirected stderr into a
TERMINATING ``NativeCommandError`` when ``$ErrorActionPreference`` is ``Stop``;
pwsh 7 leaves it as ordinary data. Run.ps1 sets ``Stop`` globally, so the two
functions that redirect a child's stderr - ``Test-PythonSpec`` and
``Invoke-Python`` - behaved differently on the two hosts, and CI only ever ran
pwsh. Every test here therefore fans out over EVERY PowerShell host present
rather than the first one found; on Windows that is both.

The candidates are real Python processes running tiny shims, because the
failure modes being pinned are about what a child writes and what it exits
with. A cmd.exe stand-in quotes its arguments differently on the two hosts and
would test the harness instead of the launcher.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tests.launcher_helpers import (
    every_powershell_host,
    extract_function,
    requires_pwsh,
    run_powershell,
)

pytestmark = [requires_pwsh, every_powershell_host]

# A candidate that prints a banner before the version - conda and some venv
# activations do exactly this. "$output" joins the lines, so the first
# `.`-separated part is "conda-banner: activating env 3", which [int] rejects.
BANNER_SHIM = """
print("conda-banner: activating env")
print("3.12.1")
"""

# The Microsoft Store python3.exe app-execution alias: found by Get-Command,
# writes its notice to stderr, exits 9009. It is always a candidate on a stock
# Windows box, and it always sits between `py` and `python` in the chain.
STORE_ALIAS_SHIM = """
import sys
sys.stderr.write("Python was not found; run without arguments to install\\n")
sys.exit(9009)
"""

# `python -m pip --version` in an environment built with `venv --without-pip`.
NO_PIP_SHIM = r"""
import sys
sys.stderr.write("No module named pip\n")
sys.exit(1)
"""

# A successful `pip install` that emitted one warning line. Exit 0 WITH stderr.
PIP_WARNING_SHIM = r"""
import sys
sys.stderr.write("WARNING: You are using pip version 22.0.4\n")
print("Successfully installed click-8.1.7")
sys.exit(0)
"""


def _shim(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / f"{name}.py"
    path.write_text(body, encoding="utf-8")
    return path


def _run(tmp_path: Path, ps_host: str, body: str, *functions: str) -> str:
    """Run `body` against functions lifted verbatim out of the shipped Run.ps1."""
    parts = [
        "Set-StrictMode -Version 2.0",
        # The preference the launcher itself sets. It is the whole subject.
        '$ErrorActionPreference = "Stop"',
        # Invoke-Python logs through this; the log file is not what is under test.
        "function Write-RunLog { param([string] $Level, [string] $Message) }",
        *(extract_function(name) for name in functions),
        body,
    ]
    script = tmp_path / "probe.ps1"
    script.write_text("\n".join(parts), encoding="utf-8")
    proc = run_powershell(ps_host, script)
    return (proc.stdout or "") + (proc.stderr or "")


def _spec(command: str, *args: str) -> str:
    quoted = ", ".join(f"'{a}'" for a in args)
    return f"New-PythonSpec -Command '{command}' -Arguments @({quoted})"


# ---------------------------------------------------------------------------
# W1 - Test-PythonSpec must answer "no", never throw. An exception escapes the
# foreach in Find-SystemPython, so a bad candidate kills the whole fallback
# chain instead of yielding to the next one.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,shim",
    [
        pytest.param("banner", BANNER_SHIM, id="stdout-banner"),
        pytest.param("store_alias", STORE_ALIAS_SHIM, id="store-alias-stderr"),
    ],
)
def test_probe_rejects_a_broken_candidate_without_throwing(tmp_path, ps_host, name, shim):
    path = _shim(tmp_path, name, shim)
    body = f"""
try {{
    $result = Test-PythonSpec ({_spec(sys.executable, str(path))})
    [Console]::WriteLine("RESULT=$result")
}} catch {{
    [Console]::WriteLine("THREW=$($_.Exception.Message)")
}}
"""
    out = _run(tmp_path, ps_host, body, "New-PythonSpec", "Test-PythonSpec")
    assert "THREW=" not in out, f"the probe threw instead of rejecting {name}: {out}"
    assert "RESULT=False" in out, out


def test_a_broken_candidate_does_not_end_the_fallback_chain(tmp_path, ps_host):
    """The user-visible bug: `py` fails, so a working `python3` is never tried."""
    broken = _shim(tmp_path, "store_alias", STORE_ALIAS_SHIM)
    body = f"""
$candidates = @(
    ({_spec(sys.executable, str(broken))}),
    ({_spec(sys.executable)})
)
$picked = "none"
foreach ($candidate in $candidates) {{
    if (Test-PythonSpec $candidate) {{
        $picked = $candidate.Args -join " "
        break
    }}
}}
[Console]::WriteLine("PICKED=[$picked]")
"""
    out = _run(tmp_path, ps_host, body, "New-PythonSpec", "Test-PythonSpec")
    assert "PICKED=[]" in out, f"the working interpreter after the bad one was never reached: {out}"


# ---------------------------------------------------------------------------
# W2 - Invoke-Python must return the child's exit code. Throwing on stderr
# makes the ensurepip recovery in Install-Dependencies unreachable, and aborts
# installs that actually succeeded but printed a warning.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,shim,expected",
    [
        pytest.param("no_pip", NO_PIP_SHIM, 1, id="missing-pip-exit-1"),
        pytest.param("pip_warning", PIP_WARNING_SHIM, 0, id="warning-on-exit-0"),
    ],
)
def test_invoke_python_returns_the_exit_code_despite_stderr(
    tmp_path, ps_host, name, shim, expected
):
    path = _shim(tmp_path, name, shim)
    body = f"""
try {{
    $code = Invoke-Python ({_spec(sys.executable, str(path))}) @()
    [Console]::WriteLine("CODE=$code")
}} catch {{
    [Console]::WriteLine("THREW=$($_.Exception.Message)")
}}
"""
    out = _run(tmp_path, ps_host, body, "New-PythonSpec", "Invoke-Python")
    assert "THREW=" not in out, f"child stderr became a terminating error for {name}: {out}"
    assert f"CODE={expected}" in out, out


# ---------------------------------------------------------------------------
# W3 - the long-option redaction rule stopped at the first space, so the tail
# of a quoted secret reached the log. The -p rule beside it already handled
# quoting; only one of the two branches had been fixed.
# ---------------------------------------------------------------------------

SECRET_TAIL = "TAIL_MUST_NOT_LEAK"


@pytest.mark.parametrize(
    "option",
    [
        "--token",
        "--password",
        "--share-password",
        "--vault-passphrase",
        "--mfa-code",
        "--elc-api-key",
    ],
)
@pytest.mark.parametrize("quote", ['"', "'"])
def test_quoted_long_option_values_are_fully_redacted(tmp_path, ps_host, option, quote):
    text = f"download L {option} {quote}hunter2 {SECRET_TAIL}{quote} -o out"
    # A PowerShell single-quoted literal, so nothing in the sample is expanded.
    # The doubling is what lets the sample itself contain single quotes.
    literal = "'" + text.replace("'", "''") + "'"
    body = f"""
$text = {literal}
[Console]::WriteLine("OUT=" + (Get-RedactedText $text))
"""
    out = _run(tmp_path, ps_host, body, "Get-RedactedText")
    assert SECRET_TAIL not in out, f"the tail of a quoted {option} value survived redaction: {out}"
    assert "<redacted>" in out, out
    # The option name and unrelated arguments must survive.
    assert option in out and "-o out" in out, out
