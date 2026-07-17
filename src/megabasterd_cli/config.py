"""Application configuration: paths, defaults, persisted settings."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

APP_NAME = "megabasterd-cli"
APP_AUTHOR = "MegaBasterdCLI"

log = logging.getLogger(__name__)

# Settings that existed but never worked; keeping them silently would lie to
# users, so setting them is rejected with the reason and old persisted values
# are ignored with a warning.
DEPRECATED_CONFIG_KEYS = {
    "chunk_size_kb": "MEGA chunk sizes are protocol-defined; this setting never had an effect "
    "and was removed.",
    "smart_proxy_autorefresh_minutes": "not implemented; the proxy pool is reloaded on every "
    "command run.",
    "smart_proxy_timeout_seconds": "not implemented; use `mb proxy fetch --timeout` instead.",
    "smart_proxy_random": "not implemented; the pool always picks randomly, weighted by health.",
}


@dataclass
class Config:
    """User-tunable settings."""

    download_path: str = ""  # Defaults to <project>/Output
    max_workers: int = 8
    upload_workers: int = 4
    max_parallel_downloads: int = 6  # Number of files downloading simultaneously
    max_parallel_uploads: int = 1  # Number of files uploading simultaneously
    speed_limit_kbps: float = 0  # Aggregate per-command download cap; 0 = unlimited
    upload_speed_limit_kbps: float = 0  # Aggregate per-command upload cap; 0 = unlimited
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
    user_agent: str = ""  # Empty = "MegaBasterd-CLI/<version>"
    megacrypter_server: str | None = None  # Default MegaCrypter server for `crypter` commands
    elc_accounts: dict[str, dict[str, str]] = field(default_factory=dict)

    # Quota recovery: wait this many seconds when MEGA returns EOVERQUOTA/-17
    quota_wait_seconds: int = 3600
    quota_max_wait_loops: int = 24  # ~24h with the default

    # Post-transfer hook: run this command (with the transferred path appended
    # as exactly one argument) after every successful download/upload.
    run_command: str | None = None

    # Upload log file (one JSON line per upload; useful for batch jobs).
    upload_log_path: str | None = None

    # Smart proxy extras
    force_smart_proxy: bool = False  # Refuse direct connections

    # CONNECT proxy server
    connect_proxy_port: int = 9999
    connect_proxy_password: str | None = None
    connect_proxy_allow_any_port: bool = False


# Range/format rules applied on load and on `config set`. Each entry maps the
# key to (predicate, human-readable requirement).
_VALIDATORS: dict[str, tuple] = {
    "max_workers": (lambda v: 1 <= v <= 64, "an integer between 1 and 64"),
    "upload_workers": (lambda v: 1 <= v <= 64, "an integer between 1 and 64"),
    "max_parallel_downloads": (lambda v: 1 <= v <= 32, "an integer between 1 and 32"),
    "max_parallel_uploads": (lambda v: 1 <= v <= 32, "an integer between 1 and 32"),
    "speed_limit_kbps": (lambda v: v >= 0, "a non-negative number"),
    "upload_speed_limit_kbps": (lambda v: v >= 0, "a non-negative number"),
    "timeout_seconds": (lambda v: v > 0, "a positive integer"),
    "quota_wait_seconds": (lambda v: v >= 0, "a non-negative integer"),
    "quota_max_wait_loops": (lambda v: v >= 0, "a non-negative integer"),
    "streaming_port": (lambda v: 1 <= v <= 65535, "a port between 1 and 65535"),
    "connect_proxy_port": (lambda v: 1 <= v <= 65535, "a port between 1 and 65535"),
    "log_max_bytes": (lambda v: v >= 0, "a non-negative integer"),
    "log_backups": (lambda v: v >= 0, "a non-negative integer"),
    "log_level": (
        lambda v: str(v).upper() in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"},
        "one of DEBUG/INFO/WARNING/ERROR/CRITICAL",
    ),
}


def validate_config_value(key: str, value) -> None:
    """Raise ValueError when `value` is out of range for `key`."""
    rule = _VALIDATORS.get(key)
    if rule is None:
        return
    predicate, requirement = rule
    try:
        ok = bool(predicate(value))
    except TypeError:
        ok = False
    if not ok:
        raise ValueError(f"{key} must be {requirement} (got {value!r})")


def validate_config(cfg: Config) -> list[str]:
    """Validate a loaded Config in place; invalid values fall back to defaults.

    Returns human-readable warnings (also logged) instead of crashing deep in
    runtime code when a hand-edited config file holds a bad value.
    """
    warnings: list[str] = []
    defaults = Config()
    for f in fields(Config):
        current = getattr(cfg, f.name)
        default = getattr(defaults, f.name)
        # Type check against the default's runtime type (None-able keys skip).
        if default is not None and current is not None:
            expected = type(default)
            if expected in (int, float) and isinstance(current, bool):
                pass  # bool is an int; treat as wrong type below only for numerics
            if expected is float and isinstance(current, int) and not isinstance(current, bool):
                current = float(current)
                setattr(cfg, f.name, current)
            elif not isinstance(current, expected) or (
                expected in (int, float) and isinstance(current, bool)
            ):
                warnings.append(
                    f"config: {f.name} has invalid type {type(current).__name__}; "
                    f"using default {default!r}"
                )
                setattr(cfg, f.name, default)
                continue
        try:
            validate_config_value(f.name, getattr(cfg, f.name))
        except ValueError as exc:
            warnings.append(f"config: {exc}; using default {default!r}")
            setattr(cfg, f.name, default)
    for message in warnings:
        log.warning("%s", message)
    return warnings


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
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            cfg = Config()
            cfg.download_path = str(default_download_dir())
            return cfg

        cfg = Config()
        for key, value in data.items():
            if key in DEPRECATED_CONFIG_KEYS:
                log.warning(
                    "config: ignoring deprecated key %s (%s)", key, DEPRECATED_CONFIG_KEYS[key]
                )
                continue
            if hasattr(cfg, key):
                setattr(cfg, key, value)
        validate_config(cfg)
        if cfg.user_agent == "MegaBasterd-CLI/1.0":
            # Old persisted default carried a hard-coded version; empty means
            # "derive from the installed package version".
            cfg.user_agent = ""
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
        if key in DEPRECATED_CONFIG_KEYS:
            raise ValueError(f"{key} is deprecated: {DEPRECATED_CONFIG_KEYS[key]}")
        if not hasattr(self.config, key):
            raise KeyError(f"Unknown config key: {key}")
        # Cast to the existing type when feasible
        current = getattr(self.config, key)
        if isinstance(current, bool):
            lowered = str(value).strip().lower()
            if lowered in ("1", "true", "yes", "y", "on"):
                value = True
            elif lowered in ("0", "false", "no", "n", "off"):
                value = False
            else:
                raise ValueError("Expected a boolean value: true/false, yes/no, on/off, or 1/0")
        elif isinstance(current, dict):
            value = json.loads(value)
            if not isinstance(value, dict):
                raise ValueError("Expected a JSON object")
        elif isinstance(current, int):
            value = int(value)
        elif isinstance(current, float):
            value = float(value)
        validate_config_value(key, value)
        setattr(self.config, key, value)
        self.save()

    def reset(self) -> None:
        self._config = Config()
        self._config.download_path = str(default_download_dir())
        self.save()
