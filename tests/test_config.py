from pathlib import Path

from megabasterd_cli.config import ConfigStore, config_file, data_dir, default_download_dir, user_dir


def test_default_download_dir_uses_project_output(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("MEGABASTERD_PROJECT_ROOT", str(tmp_path))

    assert default_download_dir() == tmp_path / "Output"


def test_new_config_defaults_to_project_output(monkeypatch, tmp_path: Path):
    project_root = tmp_path / "project"
    monkeypatch.setenv("MEGABASTERD_PROJECT_ROOT", str(project_root))

    cfg = ConfigStore(tmp_path / "config.json").load()

    assert cfg.download_path == str(project_root / "Output")


def test_user_paths_use_project_user_dir(monkeypatch, tmp_path: Path):
    project_root = tmp_path / "project"
    monkeypatch.setenv("MEGABASTERD_PROJECT_ROOT", str(project_root))
    monkeypatch.delenv("MEGABASTERD_USER_DIR", raising=False)

    assert user_dir() == project_root / "User"
    assert config_file() == project_root / "User" / "Config" / "config.json"
    assert data_dir() == project_root / "User" / "Data"


def test_user_dir_env_override(monkeypatch, tmp_path: Path):
    user_root = tmp_path / "custom-user"
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(user_root))

    assert user_dir() == user_root


def test_invalid_config_still_defaults_to_project_output(monkeypatch, tmp_path: Path):
    project_root = tmp_path / "project"
    config_path = tmp_path / "config.json"
    config_path.write_text("{bad json", encoding="utf-8")
    monkeypatch.setenv("MEGABASTERD_PROJECT_ROOT", str(project_root))

    cfg = ConfigStore(config_path).load()

    assert cfg.download_path == str(project_root / "Output")


def test_logging_defaults_are_enabled(tmp_path: Path):
    cfg = ConfigStore(tmp_path / "missing.json").load()

    assert cfg.max_workers == 8
    assert cfg.max_parallel_downloads == 6
    assert cfg.log_level == "WARNING"
    assert cfg.log_to_file is True
    assert cfg.log_max_bytes > 0
    assert cfg.log_backups >= 1
