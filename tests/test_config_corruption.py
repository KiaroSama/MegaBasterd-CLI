"""Corrupt config files are preserved, never rewritten, and recoverable.

A malformed config used to load as defaults; the next `config set` then
overwrote the user's file. Now corruption blocks every mutation until an
explicit `mb config recover --reset`.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from megabasterd_cli.cli import cli
from megabasterd_cli.config import ConfigCorruptionError, ConfigLockError, ConfigStore

MALFORMED = b'{"max_workers": 8,,,\n'
# A secret-looking value inside the corrupt file must never reach output.
SECRET_IN_FILE = b'{"connect_proxy_password": "s3cr3t-not-a-real-password", oops}'


def _runner() -> CliRunner:
    try:
        return CliRunner(mix_stderr=False)
    except TypeError:  # click >= 8.2 always separates the streams
        return CliRunner()


def _store(tmp_path, data: bytes) -> ConfigStore:
    path = tmp_path / "config.json"
    path.write_bytes(data)
    return ConfigStore(path=path, lock_timeout=0.5)


@pytest.mark.parametrize(
    "data",
    [
        MALFORMED,
        b"\xff\xfe not utf-8 at all",
        b"[1, 2, 3]",
        b'"just a string"',
        b"12345",
        b"null",
    ],
    ids=["malformed", "invalid-utf8", "list-root", "string-root", "number-root", "null-root"],
)
def test_corrupt_roots_are_detected_and_never_rewritten(tmp_path, data):
    store = _store(tmp_path, data)
    store.load()
    assert store.is_corrupt, "malformed/invalid-root config must be flagged as corrupt"
    for mutate in (
        lambda: store.set("max_workers", "4"),
        lambda: store.unset("default_account"),
        lambda: store.migrate(),
        lambda: store.reset(),
        lambda: store.save(),
    ):
        with pytest.raises(ConfigCorruptionError):
            mutate()
    assert store.path.read_bytes() == data, "the original must survive byte-for-byte"


def test_backup_is_created_once_not_on_every_read(tmp_path):
    store = _store(tmp_path, MALFORMED)
    for _ in range(5):
        store.load()
    backups = list(tmp_path.glob("config.json.corrupt.*"))
    assert len(backups) == 1, "exactly one timestamped backup, not one per read"
    assert backups[0].read_bytes() == MALFORMED


def test_concurrent_loads_make_one_backup(tmp_path):
    import threading

    path = tmp_path / "config.json"
    path.write_bytes(MALFORMED)
    stores = [ConfigStore(path=path, lock_timeout=5.0) for _ in range(6)]
    barrier = threading.Barrier(len(stores))

    def _load(store: ConfigStore) -> None:
        barrier.wait()
        store.load()

    threads = [threading.Thread(target=_load, args=(s,)) for s in stores]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(list(tmp_path.glob("config.json.corrupt.*"))) == 1
    assert path.read_bytes() == MALFORMED


def test_recover_writes_defaults_and_keeps_the_backup(tmp_path):
    store = _store(tmp_path, MALFORMED)
    store.load()
    backup = store.recover()
    assert backup is not None and backup.read_bytes() == MALFORMED
    assert not store.is_corrupt
    restored = json.loads(store.path.read_text(encoding="utf-8"))
    assert restored["max_workers"] == 8, "recovery writes a valid default config"
    store.set("max_workers", "5")  # mutations work again
    assert json.loads(store.path.read_text(encoding="utf-8"))["max_workers"] == 5


def test_corruption_message_never_leaks_file_contents(tmp_path):
    store = _store(tmp_path, SECRET_IN_FILE)
    store.load()
    assert "s3cr3t" not in store.corruption_reason


# ---------------------------------------------------------------------------
# CLI surface: every mutation exits non-zero, no traceback, nothing rewritten.
# ---------------------------------------------------------------------------


@pytest.fixture()
def corrupt_env(tmp_path, monkeypatch):
    user = tmp_path / "User"
    (user / "Config").mkdir(parents=True)
    (user / "Config" / "config.json").write_bytes(MALFORMED)
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(user))
    monkeypatch.setenv("MEGABASTERD_PROJECT_ROOT", str(tmp_path))
    return user / "Config" / "config.json"


@pytest.mark.parametrize(
    "args",
    [
        ["config", "set", "max_workers", "4"],
        ["config", "unset", "default_account"],
        ["config", "migrate"],
        ["config", "reset"],
    ],
)
def test_cli_mutations_fail_cleanly_while_corrupt(corrupt_env, args):
    result = _runner().invoke(cli, args, input="y\n")
    assert result.exit_code != 0
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Traceback" not in (result.output + (result.stderr or ""))
    assert corrupt_env.read_bytes() == MALFORMED


def test_cli_recover_reports_then_resets(corrupt_env):
    runner = _runner()
    status = runner.invoke(cli, ["config", "recover"])
    assert status.exit_code != 0, "reporting mode must signal the corruption"
    assert corrupt_env.read_bytes() == MALFORMED, "reporting must not rewrite anything"

    fixed = runner.invoke(cli, ["config", "recover", "--reset"])
    assert fixed.exit_code == 0
    assert json.loads(corrupt_env.read_text(encoding="utf-8"))["max_workers"] == 8
    backups = list(corrupt_env.parent.glob("config.json.corrupt.*"))
    assert len(backups) == 1 and backups[0].read_bytes() == MALFORMED


def test_cli_read_only_commands_do_not_rewrite(corrupt_env):
    runner = _runner()
    assert runner.invoke(cli, ["config", "show"]).exit_code == 0
    assert runner.invoke(cli, ["config", "get", "max_workers"]).exit_code == 0
    assert corrupt_env.read_bytes() == MALFORMED


def test_cli_no_secret_from_corrupt_file_in_output(tmp_path, monkeypatch):
    user = tmp_path / "User"
    (user / "Config").mkdir(parents=True)
    (user / "Config" / "config.json").write_bytes(SECRET_IN_FILE)
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(user))
    monkeypatch.setenv("MEGABASTERD_PROJECT_ROOT", str(tmp_path))
    result = _runner().invoke(cli, ["config", "recover"])
    assert "s3cr3t" not in (result.output + (result.stderr or ""))


# ---------------------------------------------------------------------------
# MF5: lock contention on reset/recover exits non-zero without a traceback.
# ---------------------------------------------------------------------------


def _lock_stuck(monkeypatch):
    from megabasterd_cli.utils import filelock

    def _boom(self, timeout=None):
        raise filelock.FileLockError("Could not lock the config file within 0s.")

    monkeypatch.setattr(filelock.FileLock, "acquire", _boom)


@pytest.fixture()
def valid_env(tmp_path, monkeypatch):
    user = tmp_path / "User"
    (user / "Config").mkdir(parents=True)
    path = user / "Config" / "config.json"
    path.write_text(json.dumps({"max_workers": 7}), encoding="utf-8")
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(user))
    monkeypatch.setenv("MEGABASTERD_PROJECT_ROOT", str(tmp_path))
    return path


@pytest.mark.parametrize(
    "args",
    [["config", "reset"], ["config", "recover", "--reset"], ["config", "set", "log_backups", "3"]],
)
def test_lock_timeout_exits_non_zero_without_traceback(valid_env, monkeypatch, args):
    before = valid_env.read_bytes()
    _lock_stuck(monkeypatch)
    result = _runner().invoke(cli, args, input="y\n")
    assert result.exit_code != 0
    assert "Traceback" not in (result.output + (result.stderr or ""))
    assert valid_env.read_bytes() == before, "a lock failure must leave the file intact"


def test_declined_reset_is_success_and_writes_nothing(valid_env):
    before = valid_env.read_bytes()
    result = _runner().invoke(cli, ["config", "reset"], input="n\n")
    assert result.exit_code == 0
    assert valid_env.read_bytes() == before


def test_confirmed_reset_succeeds(valid_env):
    result = _runner().invoke(cli, ["config", "reset"], input="y\n")
    assert result.exit_code == 0
    assert json.loads(valid_env.read_text(encoding="utf-8"))["max_workers"] == 8


def test_store_reset_raises_config_lock_error(tmp_path, monkeypatch):
    store = ConfigStore(path=tmp_path / "config.json", lock_timeout=0.1)
    _lock_stuck(monkeypatch)
    with pytest.raises(ConfigLockError):
        store.reset()
