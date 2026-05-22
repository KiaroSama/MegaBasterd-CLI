"""Launcher contract tests."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_run_ps1_exists_and_dispatches_package():
    launcher = ROOT / "Run.ps1"
    assert launcher.is_file()
    text = launcher.read_text(encoding="utf-8")
    assert "requirements.txt" in text
    assert "src" in text
    assert '-m", "megabasterd_cli' in text
    assert "Logs" in text
    assert "MEGABASTERD_CLI_LOG_FILE" in text
    assert "Write-LauncherBanner" in text
    assert "MegaBasterd-CLI" in text
    assert "Logging to: $LauncherLogPath" in text
    assert "#FF3273" in text
    assert "Get-Ansi256Color 227" in text
    assert "Checking prerequisites..." in text
    assert "No command was supplied. Showing help" not in text
    assert "defaulting to --help" not in text
    assert "Invoke-LauncherMenu" in text
    assert "Read-MenuChoice" in text
    assert "Test-LauncherExitRequested" in text
    assert "Download MEGA link/file" in text
    assert "Settings" in text
    assert "Selection [1] {quit=exit}: " in text
    assert "Selection [1] {back=0, quit=exit}: " in text
    assert 'return "exit"' in text
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
    assert "#FF8C00" in text
    assert "#00AEEF" in text
    assert "menuDefault" in text


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
