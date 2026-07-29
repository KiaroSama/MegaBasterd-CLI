"""The batch-completion hook: ONE notification per run, not one per file.

`run_command` fires per transferred file, so it cannot express "everything is
done" - the last file's hook has no way to know it was the last. Upstream
MegaBasterd notifies when ALL downloads / ALL uploads have finished; that is
the event `all_finished_command` provides: exactly one spawn per `mb download`
/ `mb upload` invocation, with `<kind> <succeeded> <failed>` appended.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

import megabasterd_cli.utils.hooks as hooks_module
from megabasterd_cli.cli import cli
from megabasterd_cli.config import Config, ConfigStore
from megabasterd_cli.core.client import MegaClient, MegaSession
from megabasterd_cli.core.downloader import DownloadResult, MegaDownloader
from megabasterd_cli.core.errors import MegaError, TransferError
from megabasterd_cli.core.uploader import MegaUploader, UploadResult
from megabasterd_cli.utils.hooks import run_all_finished_command

FILE_URL = "https://mega.nz/file/abc123#xyz"
FILE_URL_2 = "https://mega.nz/file/def456#uvw"
HOOK = "notify.exe --flag"


# ---------------------------------------------------------------------------
# Scaffolding
# ---------------------------------------------------------------------------


def _popen_shim(record):
    """A stand-in for the `subprocess` module as `hooks.py` uses it.

    Deliberately NOT `monkeypatch.setattr(hooks_module.subprocess, "Popen")`:
    that patches the real, shared `subprocess` module, so an unrelated
    `subprocess.run` elsewhere in the CLI (locking down the vault with
    `icacls`) both lands in the capture list and breaks, because `run` uses
    `Popen` as a context manager. Rebinding the module ATTRIBUTE captures hook
    spawns only and leaves the rest of the process alone.
    """
    return SimpleNamespace(Popen=record, DEVNULL=subprocess.DEVNULL)


@pytest.fixture()
def spawns(monkeypatch):
    """Capture every hook process the run would have started."""
    calls: list[tuple[list[str], dict]] = []

    def fake_popen(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return None

    monkeypatch.setattr(hooks_module, "subprocess", _popen_shim(fake_popen))
    return calls


def _configure(tmp_path: Path, **values) -> None:
    directory = tmp_path / "user" / "Config"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "config.json").write_text(json.dumps(values), encoding="utf-8")


@pytest.fixture()
def download_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))
    _configure(tmp_path, all_finished_command=HOOK)
    return tmp_path


@pytest.fixture()
def upload_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))
    _configure(tmp_path, all_finished_command=HOOK)

    from megabasterd_cli.accounts.manager import AccountManager
    from megabasterd_cli.config import accounts_file

    mgr = AccountManager(accounts_file())
    mgr.unlock("pp")
    mgr.add_account("a@example.com", "pw-a", make_default=True)

    def fake_login(self, email, password, mfa_code=None, mfa_prompt=None):
        self.session = MegaSession(sid=f"sid-{email}", master_key=b"\x00" * 16, email=email)
        return self.session

    monkeypatch.setattr(MegaClient, "login", fake_login)
    monkeypatch.setattr(MegaClient, "logout", lambda self: None)
    return tmp_path


def _downloader(failing: str | None = None):
    def download_link(self, url, output_dir, **kwargs):
        if failing and failing in url:
            raise TransferError(message="link failed")
        path = Path(output_dir) / (url.split("/file/")[1].split("#")[0] + ".bin")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")
        return DownloadResult(path=path, size=1, elapsed_seconds=0.1, integrity_ok=True)

    return download_link


def _uploader(failing: str | None = None):
    def upload_file(self, source, **kwargs):
        if failing and source.name == failing:
            raise MegaError(message="upload failed")
        return UploadResult(file_handle="H", name=source.name, size=64, elapsed_seconds=0.1)

    return upload_file


def _hook_calls(spawns) -> list[list[str]]:
    return [argv for argv, _kwargs in spawns]


# ---------------------------------------------------------------------------
# Config key
# ---------------------------------------------------------------------------


def test_config_key_is_a_nullable_string_like_run_command(tmp_path):
    """Declared, defaulted and validated exactly like the per-file hook key."""
    assert Config().all_finished_command is None
    store = ConfigStore(tmp_path / "config.json")
    store.set("all_finished_command", "shutdown.exe")
    assert store.config.all_finished_command == "shutdown.exe"
    store.unset("all_finished_command")
    assert store.config.all_finished_command is None


def test_config_key_rejects_a_non_string_and_falls_back(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"all_finished_command": 17}), encoding="utf-8")
    assert ConfigStore(path).load().all_finished_command is None


# ---------------------------------------------------------------------------
# Download batches
# ---------------------------------------------------------------------------


def test_download_batch_hook_fires_once_for_parallel_files(download_env, spawns, monkeypatch):
    """Once per invocation - NOT once per parallel worker."""
    monkeypatch.setattr(MegaDownloader, "download_link", _downloader())
    result = CliRunner().invoke(
        cli,
        ["-q", "download", FILE_URL, FILE_URL_2, "-P", "2", "-o", str(download_env / "out")],
    )
    assert result.exit_code == 0, result.output
    assert len(spawns) == 1, f"expected one batch hook, got {_hook_calls(spawns)}"
    argv, kwargs = spawns[0]
    assert argv[0] == "notify.exe"
    assert argv[-3:] == ["download", "2", "0"]
    assert kwargs.get("shell") in (None, False), "hooks must never run through a shell"


def test_download_batch_hook_fires_when_some_items_failed(download_env, spawns, monkeypatch):
    monkeypatch.setattr(MegaDownloader, "download_link", _downloader(failing="def456"))
    result = CliRunner().invoke(
        cli,
        ["-q", "download", FILE_URL, FILE_URL_2, "-P", "2", "-o", str(download_env / "out")],
    )
    assert result.exit_code == 1, result.output
    assert len(spawns) == 1
    assert spawns[0][0][-3:] == ["download", "1", "1"]


def test_unusable_links_still_end_the_batch(download_env, spawns, monkeypatch):
    """A link that never became a job is a failed item, not a missing batch."""
    monkeypatch.setattr(MegaDownloader, "download_link", _downloader())
    result = CliRunner().invoke(
        cli,
        ["-q", "download", FILE_URL, "https://example.com/not-mega", "-o", str(download_env / "o")],
    )
    assert result.exit_code == 1, result.output
    assert len(spawns) == 1
    assert spawns[0][0][-3:] == ["download", "1", "1"]


def test_empty_download_batch_does_not_fire_the_hook(download_env, spawns):
    links = download_env / "links.txt"
    links.write_text("# only comments\n\n", encoding="utf-8")
    result = CliRunner().invoke(
        cli, ["-q", "download", "-i", str(links), "-o", str(download_env / "out")]
    )
    assert result.exit_code == 2
    assert spawns == [], "nothing was transferred, so no batch finished"


def test_a_broken_batch_hook_does_not_fail_the_batch(download_env, monkeypatch):
    """A hook that cannot be started is reported, never fatal."""
    attempts: list[list[str]] = []

    def boom(argv, **kwargs):
        attempts.append(list(argv))
        raise OSError("hook executable not found")

    monkeypatch.setattr(hooks_module, "subprocess", _popen_shim(boom))
    monkeypatch.setattr(MegaDownloader, "download_link", _downloader())
    result = CliRunner().invoke(cli, ["-q", "download", FILE_URL, "-o", str(download_env / "out")])
    assert result.exit_code == 0, result.output
    assert len(attempts) == 1, "the batch hook was never attempted"


# ---------------------------------------------------------------------------
# Upload batches
# ---------------------------------------------------------------------------


def test_upload_batch_hook_fires_once_for_parallel_files(upload_env, spawns, monkeypatch):
    from tests.upload_helpers import files as _files

    monkeypatch.setattr(MegaUploader, "upload_file", _uploader())
    files = _files(upload_env, 3)
    result = CliRunner().invoke(
        cli, ["-q", "upload", *files, "-P", "2", "--vault-passphrase", "pp"]
    )
    assert result.exit_code == 0, result.output
    assert len(spawns) == 1, f"expected one batch hook, got {_hook_calls(spawns)}"
    assert spawns[0][0][-3:] == ["upload", "3", "0"]


def test_upload_batch_hook_counts_a_failed_item(upload_env, spawns, monkeypatch):
    from tests.upload_helpers import files as _files

    monkeypatch.setattr(MegaUploader, "upload_file", _uploader(failing="f1.bin"))
    files = _files(upload_env, 2)
    result = CliRunner().invoke(
        cli, ["-q", "upload", *files, "-P", "2", "--vault-passphrase", "pp"]
    )
    assert result.exit_code == 1, result.output
    assert len(spawns) == 1
    assert spawns[0][0][-3:] == ["upload", "1", "1"]


def test_keep_going_directory_upload_still_ends_the_batch(upload_env, spawns, monkeypatch):
    """--keep-going keeps the successful files AND must still fire once."""
    tree = upload_env / "tree"
    tree.mkdir()
    (tree / "ok.bin").write_bytes(b"x" * 64)
    (tree / "bad.bin").write_bytes(b"x" * 64)

    def fake_directory(self, source_dir, **kwargs):
        entries = sorted(p for p in Path(source_dir).rglob("*") if p.is_file())
        on_manifest = kwargs.get("on_manifest")
        if on_manifest:
            on_manifest([(p, p.stat().st_size) for p in entries])
        on_file_done = kwargs.get("on_file_done")
        good = next(p for p in entries if p.name == "ok.bin")
        if on_file_done:
            on_file_done(
                UploadResult(file_handle="H", name=good.name, size=64, elapsed_seconds=0.1),
                good,
            )
        bad = next(p for p in entries if p.name == "bad.bin")
        self.last_directory_failures = [f"{bad}: boom"]
        return []

    monkeypatch.setattr(MegaUploader, "upload_directory", fake_directory)
    result = CliRunner().invoke(
        cli,
        [
            "-q",
            "upload",
            str(tree),
            "--keep-structure",
            "--keep-going",
            "--vault-passphrase",
            "pp",
        ],
    )
    assert result.exit_code == 1, result.output
    assert len(spawns) == 1, f"expected one batch hook, got {_hook_calls(spawns)}"
    assert spawns[0][0][-3] == "upload"


# ---------------------------------------------------------------------------
# The hook helper itself
# ---------------------------------------------------------------------------


def test_helper_skips_an_empty_batch(spawns):
    run_all_finished_command(HOOK, kind="download", succeeded=0, failed=0)
    assert spawns == []


def test_helper_skips_an_unconfigured_hook(spawns):
    run_all_finished_command(None, kind="download", succeeded=1, failed=0)
    run_all_finished_command("", kind="download", succeeded=1, failed=0)
    assert spawns == []


def test_outcome_is_appended_as_three_argv_items(spawns):
    run_all_finished_command('tool --dir "C:\\My Files"', kind="upload", succeeded=4, failed=2)
    argv = spawns[0][0]
    assert argv[-3:] == ["upload", "4", "2"]
    assert argv[:-3] == hooks_module.parse_hook_command('tool --dir "C:\\My Files"')


def test_hook_arguments_are_not_logged(spawns, caplog):
    with caplog.at_level("INFO", logger="megabasterd_cli.utils.hooks"):
        run_all_finished_command("tool --token SUPERSECRET", kind="upload", succeeded=1, failed=0)
    joined = " ".join(record.getMessage() for record in caplog.records)
    assert "SUPERSECRET" not in joined
    assert "tool" in joined


def test_hook_never_uses_a_shell(spawns):
    run_all_finished_command(HOOK, kind="download", succeeded=1, failed=0)
    argv, kwargs = spawns[0]
    assert isinstance(argv, list)
    assert kwargs.get("shell") in (None, False)


# ---------------------------------------------------------------------------
# `queue run` - the third batch surface
# ---------------------------------------------------------------------------


@pytest.fixture()
def queue_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))
    _configure(tmp_path, all_finished_command=HOOK)
    return tmp_path


def test_a_queue_run_fires_once_for_the_whole_run(queue_env, monkeypatch, spawns):
    """The surface that most wants this hook: the one left running overnight.

    `download` and `upload` are usually watched; `queue run` is the unattended
    one, so a hook that fires for the first two and silently not for this one
    is the worst of the three gaps.
    """
    monkeypatch.setattr(MegaDownloader, "download_link", _downloader())
    runner = CliRunner()
    for url in (FILE_URL, FILE_URL_2):
        assert (
            runner.invoke(
                cli, ["-q", "queue", "add-download", url, "-o", str(queue_env / "out")]
            ).exit_code
            == 0
        )

    result = runner.invoke(cli, ["-q", "queue", "run"])

    assert result.exit_code == 0, result.output
    assert _hook_calls(spawns) == [["notify.exe", "--flag", "queue", "2", "0"]]


def test_a_queue_run_counts_a_failed_job(queue_env, monkeypatch, spawns):
    monkeypatch.setattr(MegaDownloader, "download_link", _downloader(failing="def456"))
    runner = CliRunner()
    for url in (FILE_URL, FILE_URL_2):
        assert (
            runner.invoke(
                cli, ["-q", "queue", "add-download", url, "-o", str(queue_env / "out")]
            ).exit_code
            == 0
        )

    result = runner.invoke(cli, ["-q", "queue", "run"])

    assert result.exit_code == 1, result.output
    assert _hook_calls(spawns) == [["notify.exe", "--flag", "queue", "1", "1"]]


def test_an_empty_queue_never_fires(queue_env, spawns):
    """Nothing was attempted, so there is no batch whose end to announce."""
    result = CliRunner().invoke(cli, ["-q", "queue", "run"])

    assert result.exit_code == 0, result.output
    assert _hook_calls(spawns) == []
