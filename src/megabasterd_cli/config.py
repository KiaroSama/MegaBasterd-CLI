"""Application configuration: paths, defaults, persisted settings."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path


APP_NAME = "megabasterd-cli"
APP_AUTHOR = "MegaBasterdCLI"


@dataclass
class Config:
    """User-tunable settings."""
    download_path: str = ""  # Defaults to <project>/Output
    max_workers: int = 8
    upload_workers: int = 4
    max_parallel_downloads: int = 6   # Number of files downloading simultaneously
    max_parallel_uploads: int = 1     # Number of files uploading simultaneously
    chunk_size_kb: int = 1024
    speed_limit_kbps: float = 0  # 0 = unlimited
    upload_speed_limit_kbps: float = 0
    verify_integrity: bool = True
    smart_proxy_enabled: bool = False
    smart_proxy_url: str | None = None
    timeout_seconds: int = 60
    auto_resume: bool = True
    keep_state_files_on_error: bool = True
    default_account: str | None = None
    streaming_port: int = 8080
    streaming_host: str = "127.0.0.1"
    log_level: str = "WARNING"
    log_to_file: bool = True
    log_max_bytes: int = 5_000_000
    log_backups: int = 5
    user_agent: str = "MegaBasterd-CLI/1.0"
    megacrypter_server: str | None = None  # Default MegaCrypter server for `crypter` commands
    elc_accounts: dict[str, dict[str, str]] = field(default_factory=dict)

    # Quota recovery: wait this many seconds when MEGA returns EOVERQUOTA/-17
    quota_wait_seconds: int = 3600
    quota_max_wait_loops: int = 24  # ~24h with the default

    # Post-transfer hook: run this command (with the transferred path appended)
    # after every successful download/upload.
    run_command: str | None = None

    # Upload log file (one JSON line per upload; useful for batch jobs).
    upload_log_path: str | None = None

    # Smart proxy extras
    force_smart_proxy: bool = False           # Refuse direct connections
    smart_proxy_autorefresh_minutes: int = 0  # 0 = disabled
    smart_proxy_timeout_seconds: int = 10
    smart_proxy_random: bool = True

    # CONNECT proxy server
    connect_proxy_port: int = 9999
    connect_proxy_password: str | None = None
    connect_proxy_allow_any_port: bool = False


def config_dir() -> Path:
    return user_dir() / "Config"


def data_dir() -> Path:
    return user_dir() / "Data"


def log_dir() -> Path:
    env_log = os.environ.get("MEGABASTERD_LOG_DIR")
    if env_log:
        return Path(env_log).expanduser().resolve()
    return user_dir() / "Logs"


def config_file() -> Path:
    return config_dir() / "config.json"


def accounts_file() -> Path:
    return data_dir() / "accounts.json"


def session_dir() -> Path:
    return data_dir() / "sessions"


def project_root() -> Path:
    """Return the source project root when the script launcher provides it."""
    env_root = os.environ.get("MEGABASTERD_PROJECT_ROOT")
    if env_root:
        return Path(env_root).expanduser().resolve()
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "Run.ps1").is_file():
            return parent
    return Path.cwd().resolve()


def user_dir() -> Path:
    """Directory for local user data owned by the source checkout."""
    env_user = os.environ.get("MEGABASTERD_USER_DIR")
    if env_user:
        return Path(env_user).expanduser().resolve()
    return project_root() / "User"


def default_download_dir() -> Path:
    """Default download directory used when no config override is present."""
    return project_root() / "Output"


class ConfigStore:
    """Load and save the Config dataclass from JSON on disk."""

    def __init__(self, path: Path | None = None):
        self.path = path or config_file()
        self._config: Config | None = None

    @property
    def config(self) -> Config:
        if self._config is None:
            self._config = self.load()
        return self._config

    def load(self) -> Config:
        if not self.path.exists():
            cfg = Config()
            cfg.download_path = str(default_download_dir())
            return cfg

        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            cfg = Config()
            cfg.download_path = str(default_download_dir())
            return cfg

        cfg = Config()
        for key, value in data.items():
            if hasattr(cfg, key):
                setattr(cfg, key, value)
        if not cfg.download_path:
            cfg.download_path = str(default_download_dir())
        return cfg

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(asdict(self.config), f, indent=2)
        os.replace(tmp, self.path)

    def set(self, key: str, value) -> None:
        if not hasattr(self.config, key):
            raise KeyError(f"Unknown config key: {key}")
        # Cast to the existing type when feasible
        current = getattr(self.config, key)
        if isinstance(current, bool):
            value = str(value).lower() in ("1", "true", "yes", "on")
        elif isinstance(current, dict):
            value = json.loads(value)
            if not isinstance(value, dict):
                raise ValueError("Expected a JSON object")
        elif isinstance(current, int):
            value = int(value)
        elif isinstance(current, float):
            value = float(value)
        setattr(self.config, key, value)
        self.save()

    def reset(self) -> None:
        self._config = Config()
        self._config.download_path = str(default_download_dir())
        self.save()
