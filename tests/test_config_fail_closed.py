"""A corrupt config must fail CLOSED, before any socket or mutation.

The defect: `ConfigStore.load()` returns defaults when the file is corrupt (and
flags it), but nothing at the top level checked that flag. A config that said
`force_smart_proxy: true` therefore loaded as `false`, and `mb download` opened
a DIRECT connection to the MEGA API - silently discarding the user's proxy
policy, integrity settings, paths, and limits.

Every transport below fails the test the moment a request is attempted: it is
not enough to return an error after the socket was already opened.
"""

from __future__ import annotations

import json

import pytest
import requests.sessions
from click.testing import CliRunner

from megabasterd_cli.cli import cli

MALFORMED = b'{"force_smart_proxy": true, "smart_proxy_enabled": true,,, BROKEN'

# Commands that must refuse to run at all while the config is unusable. Each
# one either opens a socket, creates a destination, or mutates stored state.
NETWORK_OR_MUTATING = [
    ["download", "https://mega.nz/file/ABCD1234#KEYMATERIAL"],
    ["info", "https://mega.nz/file/ABCD1234#KEYMATERIAL"],
    ["stream", "https://mega.nz/file/ABCD1234#KEYMATERIAL"],
    ["upload", "."],
    ["ls"],
    ["search", "term"],
    ["mkdir", "folder"],
    ["rm", "handle"],
    ["mv", "handle", "target"],
    ["rename", "handle", "newname"],
    ["share", "handle"],
    ["import", "https://mega.nz/folder/ABCD1234#KEYMATERIAL"],
    ["account", "refresh-all"],
    ["account", "info"],
    ["proxy", "fetch"],
    ["queue", "run"],
    ["queue", "add-download", "https://mega.nz/file/ABCD1234#KEYMATERIAL"],
    ["watch"],
    ["crypter", "elc-resolve", "mega://elc?QQ=="],
]

# The recovery/inspection surface stays usable: that is how the user fixes it.
RECOVERY_ALLOWED = [
    ["config", "path"],
    ["config", "show"],
    ["config", "get", "max_workers"],
    ["config", "recover"],
]


@pytest.fixture()
def corrupt_env(tmp_path, monkeypatch):
    user = tmp_path / "User"
    (user / "Config").mkdir(parents=True)
    (user / "Config" / "config.json").write_bytes(MALFORMED)
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(user))
    monkeypatch.setenv("MEGABASTERD_PROJECT_ROOT", str(tmp_path))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "Logs"))
    return user / "Config" / "config.json"


@pytest.fixture()
def no_network(monkeypatch):
    """Any outbound request at all fails the test immediately."""
    attempts: list[str] = []

    def refuse(self, method, url, **kwargs):
        attempts.append(f"{method} {url}")
        raise AssertionError(f"OUTBOUND REQUEST ATTEMPTED WITH A CORRUPT CONFIG: {method} {url}")

    monkeypatch.setattr(requests.sessions.Session, "request", refuse)
    return attempts


@pytest.mark.parametrize(
    "args", NETWORK_OR_MUTATING, ids=[" ".join(a[:2]) for a in NETWORK_OR_MUTATING]
)
def test_networked_commands_refuse_before_any_request(corrupt_env, no_network, args):
    result = CliRunner().invoke(cli, args, input="\n")
    assert no_network == [], f"{args} reached the network: {no_network}"
    assert result.exit_code != 0, f"{args} must exit non-zero with a corrupt config"
    assert "Traceback" not in result.output
    assert corrupt_env.read_bytes() == MALFORMED, "the corrupt file must be preserved"


@pytest.mark.parametrize("args", RECOVERY_ALLOWED, ids=[" ".join(a) for a in RECOVERY_ALLOWED])
def test_recovery_surface_still_runs(corrupt_env, args):
    result = CliRunner().invoke(cli, args)
    assert "Traceback" not in result.output
    # `config recover` reports the corruption (non-zero); the read-only
    # inspectors succeed. Neither may rewrite the file.
    assert corrupt_env.read_bytes() == MALFORMED


def test_explicit_recovery_still_works_end_to_end(corrupt_env):
    runner = CliRunner()
    assert runner.invoke(cli, ["config", "recover"]).exit_code != 0
    fixed = runner.invoke(cli, ["config", "recover", "--reset"])
    assert fixed.exit_code == 0
    assert json.loads(corrupt_env.read_text(encoding="utf-8"))["max_workers"] == 8
    # ...and normal commands are usable again afterwards.
    assert runner.invoke(cli, ["config", "get", "max_workers"]).exit_code == 0


def test_the_refusal_names_the_problem_without_leaking_file_contents(tmp_path, monkeypatch):
    user = tmp_path / "User"
    (user / "Config").mkdir(parents=True)
    (user / "Config" / "config.json").write_bytes(
        b'{"connect_proxy_password": "sentinel-not-a-real-secret",,, BROKEN'
    )
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(user))
    monkeypatch.setenv("MEGABASTERD_PROJECT_ROOT", str(tmp_path))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "Logs"))
    result = CliRunner().invoke(cli, ["ls"])
    assert result.exit_code != 0
    assert "sentinel-not-a-real-secret" not in result.output
    assert "config" in result.output.lower()


def test_a_valid_config_is_unaffected(tmp_path, monkeypatch):
    """The gate must not block normal operation."""
    user = tmp_path / "User"
    (user / "Config").mkdir(parents=True)
    (user / "Config" / "config.json").write_text(json.dumps({"max_workers": 4}), encoding="utf-8")
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(user))
    monkeypatch.setenv("MEGABASTERD_PROJECT_ROOT", str(tmp_path))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "Logs"))
    result = CliRunner().invoke(cli, ["config", "get", "max_workers"])
    assert result.exit_code == 0
    assert "4" in result.output
