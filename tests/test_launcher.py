"""Launcher contract tests.

Run.ps1 is now a thin entry point: it keeps only the PowerShell-specific work
(repo root, interpreter/venv prerequisites, transcript + scrub, exit code) and
hands everything else to ``megabasterd_cli.launcher_menu``. The menu contract
that used to be asserted against the PowerShell text is asserted against that
module here, and behaviourally in tests/test_launcher_menu.py.
"""

from pathlib import Path

from megabasterd_cli import launcher_menu

ROOT = Path(__file__).resolve().parents[1]


def test_run_ps1_exists_and_dispatches_package():
    launcher = ROOT / "Run.ps1"
    assert launcher.is_file()
    text = launcher.read_text(encoding="utf-8")
    assert "requirements.txt" in text
    assert "src" in text
    assert '"-m", "megabasterd_cli.launcher_menu"' in text
    assert "Logs" in text
    assert "MEGABASTERD_CLI_LOG_FILE" in text
    assert "MEGABASTERD_LAUNCHER_LOG_FILE" in text
    assert "Write-LauncherBanner" in text
    assert "MegaBasterd-CLI" in text
    assert "Logging to: $LauncherLogPath" in text
    assert "#FF3273" in text
    assert "Get-Ansi256Color 227" in text
    assert "Checking prerequisites..." in text
    assert "No command was supplied. Showing help" not in text
    assert "defaulting to --help" not in text
    assert "UserDir" in text
    assert '"Config"' in text
    assert '"Data\\sessions"' in text
    assert "Read-LauncherYesNo" in text
    assert "Install dependencies now into the project environment?" in text
    assert "(y/n)" in text
    assert "--disable-pip-version-check" in text
    assert '"--upgrade", "pip"' not in text
    assert "Launcher log:" not in text
    assert "Launcher transcript:" not in text
    assert "CLI log:" not in text
    assert "$exitCode = [int]$LASTEXITCODE" in text


def test_run_ps1_keeps_only_the_powershell_specific_work():
    """The menu, prompts and argument building must not creep back into PowerShell."""
    text = (ROOT / "Run.ps1").read_text(encoding="utf-8")
    for moved in (
        "Invoke-LauncherMenu",
        "Read-MenuChoice",
        "Write-MenuOption",
        "Invoke-DownloadWizard",
        "Invoke-GenericWizard",
        "ConvertTo-ArgumentList",
        "ConvertTo-NativeArgument",
        "Get-RedactedArgsForLog",
    ):
        assert moved not in text, f"{moved} belongs in launcher_menu.py"
    # ...while the PowerShell-only half stays put.
    for kept in (
        # The transcript is gone on purpose (see
        # tests/test_launcher_no_raw_transcript.py): it wrote the raw command
        # line to disk and scrubbed it only at exit. Redaction now happens at
        # the write, so `Get-RedactedText` is the PowerShell-side guard.
        "Get-RedactedText",
        "Find-SystemPython",
        "New-ProjectVenv",
    ):
        assert kept in text


def test_menu_contract_lives_in_the_python_launcher():
    labels = [label for label, _ in launcher_menu._main_menu().entries]
    assert labels[0] == "Download MEGA link/file"
    assert "Settings" in labels
    assert launcher_menu._nav_hint(False) == " {quit=exit}: "
    assert launcher_menu._nav_hint(True) == " {back=0, quit=exit}: "
    assert launcher_menu.QUIT_TOKEN == "exit"


def test_launcher_uses_expected_dependency_modules():
    text = (ROOT / "Run.ps1").read_text(encoding="utf-8")
    for module in [
        "click",
        "rich",
        "requests",
        "Crypto",
        "tenacity",
        "cryptography",
    ]:
        assert f'"{module}"' in text
