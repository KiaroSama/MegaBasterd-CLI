"""Centralized config validation and deprecated-key handling."""

from __future__ import annotations

import json

import pytest

from megabasterd_cli.config import (
    DEPRECATED_CONFIG_KEYS,
    Config,
    ConfigStore,
    validate_config,
    validate_config_value,
)


def _store(tmp_path) -> ConfigStore:
    return ConfigStore(tmp_path / "config.json")


def test_set_rejects_out_of_range_values(tmp_path):
    store = _store(tmp_path)
    for key, bad in [
        ("streaming_port", "0"),
        ("streaming_port", "70000"),
        ("connect_proxy_port", "-1"),
        ("timeout_seconds", "0"),
        ("max_workers", "0"),
        ("max_workers", "1000"),
        ("speed_limit_kbps", "-5"),
        ("quota_wait_seconds", "-1"),
        ("log_backups", "-2"),
        ("log_level", "CHATTY"),
    ]:
        with pytest.raises(ValueError):
            store.set(key, bad)


def test_set_accepts_valid_values(tmp_path):
    store = _store(tmp_path)
    store.set("streaming_port", "9000")
    store.set("max_workers", "16")
    store.set("speed_limit_kbps", "512")
    store.set("log_level", "info")
    assert store.config.streaming_port == 9000
    assert store.config.max_workers == 16
    assert store.config.speed_limit_kbps == 512.0


def test_hand_edited_invalid_values_fall_back_with_warning(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "streaming_port": 999999,
                "max_workers": -3,
                "timeout_seconds": "sixty",
                "verify_integrity": "yes-ish",
                "speed_limit_kbps": -1,
            }
        ),
        encoding="utf-8",
    )
    cfg = ConfigStore(path).load()
    defaults = Config()
    assert cfg.streaming_port == defaults.streaming_port
    assert cfg.max_workers == defaults.max_workers
    assert cfg.timeout_seconds == defaults.timeout_seconds
    assert cfg.verify_integrity == defaults.verify_integrity
    assert cfg.speed_limit_kbps == defaults.speed_limit_kbps


def test_validate_config_reports_and_repairs():
    cfg = Config()
    cfg.streaming_port = 0
    cfg.log_level = "NOPE"
    warnings = validate_config(cfg)
    assert len(warnings) == 2
    assert cfg.streaming_port == Config().streaming_port
    assert cfg.log_level == Config().log_level


def test_deprecated_keys_are_rejected_on_set_and_ignored_on_load(tmp_path):
    store = _store(tmp_path)
    for key in DEPRECATED_CONFIG_KEYS:
        with pytest.raises(ValueError, match="deprecated"):
            store.set(key, "1")
    # Old config files containing them still load fine.
    path = tmp_path / "old.json"
    path.write_text(
        json.dumps({"chunk_size_kb": 2048, "smart_proxy_random": False, "max_workers": 4}),
        encoding="utf-8",
    )
    cfg = ConfigStore(path).load()
    assert cfg.max_workers == 4
    assert not hasattr(cfg, "chunk_size_kb")


def test_validate_config_value_unknown_key_is_noop():
    validate_config_value("download_path", "anything")  # no rule: no exception


def test_optional_string_fields_reject_wrong_types_on_set(tmp_path):
    """MF8: None-default fields still have an expected type."""
    import megabasterd_cli.config as config_module

    for key in (
        "default_account",
        "smart_proxy_url",
        "run_command",
        "upload_log_path",
        "connect_proxy_password",
        "megacrypter_server",
    ):
        config_module.validate_config_value(key, None)  # valid
        config_module.validate_config_value(key, "some-string")  # valid
        with pytest.raises(ValueError):
            config_module.validate_config_value(key, ["list"])
        with pytest.raises(ValueError):
            config_module.validate_config_value(key, 42)


def test_optional_fields_fall_back_on_load_without_echoing_values(tmp_path, caplog):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "default_account": ["not", "a", "string"],
                "run_command": 42,
                "connect_proxy_password": {"oops": "SECRET-VALUE"},
                "upload_log_path": 3.14,
            }
        ),
        encoding="utf-8",
    )
    with caplog.at_level("WARNING"):
        cfg = ConfigStore(path).load()
    assert cfg.default_account is None
    assert cfg.run_command is None
    assert cfg.connect_proxy_password is None
    assert cfg.upload_log_path is None
    joined = " ".join(r.getMessage() for r in caplog.records)
    assert "SECRET-VALUE" not in joined, "warnings must never echo secret values"


def test_invalid_nested_elc_accounts_falls_back(tmp_path, caplog):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "elc_accounts": {
                    "host.example": {"user": "u", "api_key": 123},  # non-string leaf
                }
            }
        ),
        encoding="utf-8",
    )
    with caplog.at_level("WARNING"):
        cfg = ConfigStore(path).load()
    assert cfg.elc_accounts == {}
    joined = " ".join(r.getMessage() for r in caplog.records)
    assert "123" not in joined and "api_key" not in joined, "no nested content in warnings"


def test_valid_elc_accounts_pass(tmp_path):
    path = tmp_path / "config.json"
    payload = {"elc_accounts": {"host.example": {"user": "u", "api_key": "k"}}}
    path.write_text(json.dumps(payload), encoding="utf-8")
    cfg = ConfigStore(path).load()
    assert cfg.elc_accounts == payload["elc_accounts"]


def test_boolean_not_accepted_for_numeric_fields(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"max_workers": True, "speed_limit_kbps": False}), encoding="utf-8")
    cfg = ConfigStore(path).load()
    assert cfg.max_workers == Config().max_workers
    assert cfg.speed_limit_kbps == Config().speed_limit_kbps


def test_deprecated_and_unknown_keys_warn_once_per_process(tmp_path, caplog, monkeypatch):
    """MF10: repeated loads must not repeat the warning."""
    import megabasterd_cli.config as config_module

    monkeypatch.setattr(config_module, "_warned_config_keys", set())
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"chunk_size_kb": 1024, "totally_unknown_key": 1, "max_workers": 4}),
        encoding="utf-8",
    )
    with caplog.at_level("WARNING"):
        ConfigStore(path).load()
        ConfigStore(path).load()
        ConfigStore(path).load()
    deprecated_warnings = [r for r in caplog.records if "chunk_size_kb" in r.getMessage()]
    unknown_warnings = [r for r in caplog.records if "totally_unknown_key" in r.getMessage()]
    assert len(deprecated_warnings) == 1
    assert len(unknown_warnings) == 1


def test_migrate_removes_deprecated_keys_and_preserves_settings(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "chunk_size_kb": 2048,
                "smart_proxy_random": False,
                "totally_unknown_key": 1,
                "max_workers": 4,
                "default_account": "a@example.com",
            }
        ),
        encoding="utf-8",
    )
    store = ConfigStore(path)
    removed = store.migrate()
    assert sorted(removed) == ["chunk_size_kb", "smart_proxy_random", "totally_unknown_key"]
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert "chunk_size_kb" not in raw
    assert "smart_proxy_random" not in raw
    assert "totally_unknown_key" not in raw
    assert raw["max_workers"] == 4
    assert raw["default_account"] == "a@example.com"
    # Second migrate is a no-op.
    assert ConfigStore(path).migrate() == []


def test_old_evdlc_style_config_loads_safely(tmp_path):
    """A config written by an old external integration must load without crashing."""
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "chunk_size_kb": 1024,
                "smart_proxy_autorefresh_minutes": 30,
                "smart_proxy_timeout_seconds": 10,
                "smart_proxy_random": True,
                "user_agent": "MegaBasterd-CLI/1.0",
                "max_workers": 6,
            }
        ),
        encoding="utf-8",
    )
    cfg = ConfigStore(path).load()
    assert cfg.max_workers == 6
    assert cfg.user_agent == "", "old hard-coded UA becomes version-derived"


def test_old_hardcoded_user_agent_migrates_to_versioned(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"user_agent": "MegaBasterd-CLI/1.0"}), encoding="utf-8")
    cfg = ConfigStore(path).load()
    assert cfg.user_agent == ""  # empty means "derive from package version"

    from megabasterd_cli import __version__
    from megabasterd_cli.core.api import MegaAPIClient

    api = MegaAPIClient(user_agent=cfg.user_agent or None)
    assert api.user_agent == f"MegaBasterd-CLI/{__version__}"
