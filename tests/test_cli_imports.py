"""Smoke tests: every CLI module can be imported and the top-level group works."""

import sys

from click.testing import CliRunner

from megabasterd_cli.cli import _redacted_argv, _startup_args_for_log, cli


def test_cli_help_runs():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "MegaBasterd CLI" in result.output


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0


def test_cli_subcommands_registered():
    """Every command we promise in the README must be present in the CLI group."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    expected = [
        "download",
        "upload",
        "stream",
        "ls",
        "mkdir",
        "rm",
        "mv",
        "rename",
        "search",
        "import",
        "trash",
        "share",
        "info",
        "account",
        "queue",
        "proxy",
        "config",
        "crypter",
        "split",
        "merge",
        "thumbnail",
        "watch",
    ]
    for cmd in expected:
        assert cmd in result.output, f"Missing command: {cmd}"


def test_proxy_serve_registered():
    runner = CliRunner()
    result = runner.invoke(cli, ["proxy", "--help"])
    assert result.exit_code == 0
    assert "serve" in result.output


def test_download_has_parallel_option():
    runner = CliRunner()
    result = runner.invoke(cli, ["download", "--help"])
    assert result.exit_code == 0
    assert "--parallel" in result.output or "-P" in result.output


def test_upload_has_share_option():
    runner = CliRunner()
    result = runner.invoke(cli, ["upload", "--help"])
    assert result.exit_code == 0
    assert "--share" in result.output


def test_crypter_subcommands():
    runner = CliRunner()
    result = runner.invoke(cli, ["crypter", "--help"])
    assert result.exit_code == 0
    for sub in ["encrypt", "decrypt", "make-link", "resolve"]:
        assert sub in result.output


def test_proxy_fetch_registered():
    runner = CliRunner()
    result = runner.invoke(cli, ["proxy", "--help"])
    assert result.exit_code == 0
    assert "fetch" in result.output


def test_download_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["download", "--help"])
    assert result.exit_code == 0
    assert "--password" in result.output
    assert "--input-file" in result.output or "-i" in result.output


def test_upload_help_has_new_options():
    runner = CliRunner()
    result = runner.invoke(cli, ["upload", "--help"])
    assert result.exit_code == 0
    assert "--keep-structure" in result.output
    assert "--auto-account" in result.output


def test_share_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["share", "--help"])
    assert result.exit_code == 0
    assert "password" in result.output.lower()


def test_info_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["info", "--help"])
    assert result.exit_code == 0
    assert "no account or mfa needed" in result.output.lower()


def test_startup_log_redacts_sensitive_arguments():
    args = [
        "download",
        "https://mega.nz/file/ABC#SECRET",
        "--password",
        "secret",
        "--share-password",
        "share-secret",
        "--vault-passphrase",
        "vault-secret",
        "--elc-api-key",
        "key",
    ]

    assert _redacted_argv(args) == [
        "download",
        "<redacted-link>",
        "--password",
        "<redacted>",
        "--share-password",
        "<redacted>",
        "--vault-passphrase",
        "<redacted>",
        "--elc-api-key",
        "<redacted>",
    ]


def test_startup_args_handles_python_module_entrypoint(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            r"C:\project\src\megabasterd_cli\__main__.py",
            "download",
            "https://mega.nz/file/ABC#SECRET",
        ],
    )

    assert _startup_args_for_log() == ["download", "<redacted-link>"]
