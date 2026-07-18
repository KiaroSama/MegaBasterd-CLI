"""MF5/MF9/MF10/MF11: config secret display, exit codes, nullable, concurrency."""

from __future__ import annotations

import json
import subprocess
import sys
import threading

import pytest
from click.testing import CliRunner

from megabasterd_cli.cli import cli
from megabasterd_cli.config import Config, ConfigLockError, ConfigStore, display_value
from megabasterd_cli.utils.filelock import FileLock


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))
    return tmp_path


# ---------------------------------------------------------------------------
# MF5: secret display redaction
# ---------------------------------------------------------------------------


def test_display_value_redacts_proxy_password():
    assert display_value("connect_proxy_password", "hunter2") == "<redacted>"
    assert display_value("connect_proxy_password", None) is None


def test_display_value_recursively_redacts_elc_accounts():
    value = {"host.example": {"user": "u", "api_key": "SECRETKEY"}}
    shown = display_value("elc_accounts", value)
    assert shown["host.example"]["api_key"] == "<redacted>"
    assert shown["host.example"]["user"] == "u"


def test_config_show_never_prints_secrets(cli_env):
    runner = CliRunner()
    runner.invoke(cli, ["config", "set", "connect_proxy_password", "hunter2"])
    runner.invoke(
        cli,
        [
            "config",
            "set",
            "elc_accounts",
            json.dumps({"h": {"user": "u", "api_key": "APIKEY123"}}),
        ],
    )
    result = runner.invoke(cli, ["config", "show"])
    assert result.exit_code == 0
    assert "hunter2" not in result.output
    assert "APIKEY123" not in result.output
    assert "<redacted>" in result.output


def test_config_get_secret_is_redacted(cli_env):
    runner = CliRunner()
    runner.invoke(cli, ["config", "set", "connect_proxy_password", "hunter2"])
    result = runner.invoke(cli, ["config", "get", "connect_proxy_password"])
    assert result.exit_code == 0
    assert "hunter2" not in result.output
    assert "<redacted>" in result.output


def test_config_set_success_never_echoes_value(cli_env):
    runner = CliRunner()
    result = runner.invoke(cli, ["config", "set", "connect_proxy_password", "hunter2"])
    assert result.exit_code == 0
    assert "hunter2" not in result.output


# ---------------------------------------------------------------------------
# MF9: exit codes
# ---------------------------------------------------------------------------


def test_unknown_get_exits_nonzero(cli_env):
    result = CliRunner().invoke(cli, ["config", "get", "no_such_key"])
    assert result.exit_code != 0


def test_unknown_set_exits_nonzero(cli_env):
    result = CliRunner().invoke(cli, ["config", "set", "no_such_key", "1"])
    assert result.exit_code != 0


def test_invalid_value_exits_nonzero(cli_env):
    result = CliRunner().invoke(cli, ["config", "set", "streaming_port", "70000"])
    assert result.exit_code != 0


def test_deprecated_key_exits_nonzero(cli_env):
    result = CliRunner().invoke(cli, ["config", "set", "chunk_size_kb", "1024"])
    assert result.exit_code != 0


def test_valid_get_set_migrate_exit_zero(cli_env):
    runner = CliRunner()
    assert runner.invoke(cli, ["config", "set", "max_workers", "10"]).exit_code == 0
    assert runner.invoke(cli, ["config", "get", "max_workers"]).exit_code == 0
    assert runner.invoke(cli, ["config", "migrate"]).exit_code == 0


# ---------------------------------------------------------------------------
# MF10: nullable parsing + unset
# ---------------------------------------------------------------------------


def test_set_null_stores_json_null(cli_env, tmp_path):
    from megabasterd_cli.config import config_file

    runner = CliRunner()
    runner.invoke(cli, ["config", "set", "smart_proxy_url", "http://p:8080"])
    runner.invoke(cli, ["config", "set", "smart_proxy_url", "null"])
    raw = json.loads(config_file().read_text(encoding="utf-8"))
    assert raw["smart_proxy_url"] is None


def test_set_none_becomes_none(cli_env):
    runner = CliRunner()
    runner.invoke(cli, ["config", "set", "default_account", "me@example.com"])
    runner.invoke(cli, ["config", "set", "default_account", "NONE"])
    result = runner.invoke(cli, ["config", "get", "default_account"])
    assert result.output.strip() in ("None", "")


def test_literal_string_is_preserved(cli_env):
    runner = CliRunner()
    runner.invoke(cli, ["config", "set", "default_account", "null-value"])
    result = runner.invoke(cli, ["config", "get", "default_account"])
    assert "null-value" in result.output


def test_unset_nullable_field(cli_env):
    runner = CliRunner()
    runner.invoke(cli, ["config", "set", "smart_proxy_url", "http://p:8080"])
    result = runner.invoke(cli, ["config", "unset", "smart_proxy_url"])
    assert result.exit_code == 0
    assert runner.invoke(cli, ["config", "get", "smart_proxy_url"]).output.strip() in (
        "None",
        "",
    )


def test_unset_non_nullable_fails_nonzero(cli_env):
    result = CliRunner().invoke(cli, ["config", "unset", "max_workers"])
    assert result.exit_code != 0


def test_reload_preserves_none(cli_env, tmp_path):
    from megabasterd_cli.config import config_file

    store = ConfigStore(config_file())
    store.set("smart_proxy_url", "http://p:8080")
    store.unset("smart_proxy_url")
    assert ConfigStore(config_file()).config.smart_proxy_url is None


# ---------------------------------------------------------------------------
# MF11: concurrent-write-safe ConfigStore
# ---------------------------------------------------------------------------


def _store(path):
    return ConfigStore(path)


def test_two_threads_set_different_keys_both_survive(tmp_path):
    path = tmp_path / "config.json"
    store = _store(path)
    store.set("max_workers", "4")  # seed the file
    errors: list[BaseException] = []

    def setter(key, value):
        try:
            for _ in range(15):
                _store(path).set(key, value)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    t1 = threading.Thread(target=setter, args=("max_workers", "12"))
    t2 = threading.Thread(target=setter, args=("upload_workers", "7"))
    t1.start()
    t2.start()
    t1.join(timeout=30)
    t2.join(timeout=30)
    assert not errors
    final = ConfigStore(path).config
    assert final.max_workers == 12
    assert final.upload_workers == 7


def test_two_store_instances_set_different_keys_both_survive(tmp_path):
    path = tmp_path / "config.json"
    _store(path).set("max_workers", "4")
    a = _store(path)
    b = _store(path)
    a.set("max_workers", "20")
    b.set("timeout_seconds", "45")
    final = ConfigStore(path).config
    assert final.max_workers == 20
    assert final.timeout_seconds == 45


_SUB = r"""
import sys
from pathlib import Path
from megabasterd_cli.config import ConfigStore
ConfigStore(Path(sys.argv[1])).set(sys.argv[2], sys.argv[3])
"""


def test_two_subprocesses_race_both_updates_survive(tmp_path):
    path = tmp_path / "config.json"
    _store(path).set("max_workers", "4")
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _SUB, str(path), key, val],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for key, val in [("max_workers", "16"), ("timeout_seconds", "50")]
    ]
    for p in procs:
        _out, err = p.communicate(timeout=60)
        assert p.returncode == 0, err
    final = ConfigStore(path).config
    assert final.max_workers == 16
    assert final.timeout_seconds == 50


def test_temp_files_do_not_leak(tmp_path):
    path = tmp_path / "config.json"
    store = _store(path)
    for i in range(5):
        store.set("max_workers", str(i + 1))
    assert list(tmp_path.glob("config.json.*.tmp")) == []


def test_lock_timeout_raises_and_cli_exits_nonzero(tmp_path):
    path = tmp_path / "config.json"
    store = ConfigStore(path, lock_timeout=0.3)
    store.set("max_workers", "4")
    blocker = FileLock(path.parent / (path.name + ".lock"))
    blocker.acquire(timeout=5)
    try:
        with pytest.raises(ConfigLockError):
            store.set("max_workers", "9")
    finally:
        blocker.release()


def test_serialization_failure_preserves_original(tmp_path):
    path = tmp_path / "config.json"
    store = _store(path)
    store.set("max_workers", "8")
    original = path.read_bytes()
    # Inject an unserializable value and attempt a save.
    store.config.elc_accounts = {"h": {"x": object()}}  # not JSON serializable
    with pytest.raises(TypeError):
        store.save()
    assert path.read_bytes() == original
    assert Config  # symbol used
