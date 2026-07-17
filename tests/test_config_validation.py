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


def test_old_hardcoded_user_agent_migrates_to_versioned(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"user_agent": "MegaBasterd-CLI/1.0"}), encoding="utf-8")
    cfg = ConfigStore(path).load()
    assert cfg.user_agent == ""  # empty means "derive from package version"

    from megabasterd_cli import __version__
    from megabasterd_cli.core.api import MegaAPIClient

    api = MegaAPIClient(user_agent=cfg.user_agent or None)
    assert api.user_agent == f"MegaBasterd-CLI/{__version__}"
