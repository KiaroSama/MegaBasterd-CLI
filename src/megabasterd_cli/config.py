"""Application configuration: paths, defaults, persisted settings."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from .utils.filelock import FileLock, FileLockError

APP_NAME = "megabasterd-cli"
APP_AUTHOR = "MegaBasterdCLI"

log = logging.getLogger(__name__)


class ConfigLockError(Exception):
    """Raised when the config file lock cannot be acquired in time."""


# Nullable (None-default) fields accept an explicit "null"/"none" to unset.
_NULL_TOKENS = {"null", "none"}

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

# Deterministic warn-once bookkeeping: old config files written by other
# tools (e.g. EVdlc) may carry deprecated or unknown keys on every load;
# each key is warned about at most once per process, never per access.
_warned_config_keys: set[str] = set()

# Fields whose dataclass default is None still have an expected value type.
_OPTIONAL_STR_KEYS = {
    "default_account",
    "smart_proxy_url",
    "run_command",
    "upload_log_path",
    "connect_proxy_password",
    "megacrypter_server",
}

# Values of these keys may contain secrets and are never echoed in warnings
# or `config show`/`config get`.
_SECRET_CONFIG_KEYS = {"connect_proxy_password", "elc_accounts"}


def _warn_once(key: str, message: str) -> None:
    if key not in _warned_config_keys:
        _warned_config_keys.add(key)
        log.warning("%s", message)


def _valid_elc_accounts(value) -> bool:
    """`elc_accounts` must be {host: {field: str}} end to end."""
    if not isinstance(value, dict):
        return False
    for host, entry in value.items():
        if not isinstance(host, str) or not isinstance(entry, dict):
            return False
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in entry.items()):
            return False
    return True


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
    """Raise ValueError when `value` is invalid for `key`.

    Secret-carrying keys are validated without echoing the value.
    """
    if key in _OPTIONAL_STR_KEYS and value is not None and not isinstance(value, str):
        raise ValueError(f"{key} must be a string or null (got type {type(value).__name__})")
    if key == "elc_accounts" and not _valid_elc_accounts(value):
        raise ValueError(
            "elc_accounts must be a JSON object of the form "
            '{"host": {"user": "...", "api_key": "..."}} with string values only'
        )
    rule = _VALIDATORS.get(key)
    if rule is None:
        return
    predicate, requirement = rule
    try:
        ok = bool(predicate(value))
    except TypeError:
        ok = False
    if not ok:
        shown = "<redacted>" if key in _SECRET_CONFIG_KEYS else repr(value)
        raise ValueError(f"{key} must be {requirement} (got {shown})")


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
        # Optional (None-default) fields still have an expected type; never
        # echo their values (they may carry secrets).
        if f.name in _OPTIONAL_STR_KEYS:
            if current is not None and not isinstance(current, str):
                warnings.append(
                    f"config: {f.name} must be a string or null "
                    f"(got type {type(current).__name__}); using default"
                )
                setattr(cfg, f.name, default)
            continue
        if f.name == "elc_accounts":
            if not _valid_elc_accounts(current):
                warnings.append(
                    "config: elc_accounts has an invalid structure "
                    "(expected {host: {field: string}}); using default"
                )
                setattr(cfg, f.name, {})
            continue
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


def display_value(key: str, value):
    """Redact secret config values for `config show` / `config get`.

    `connect_proxy_password` shows `<redacted>` when set; `elc_accounts` has
    its nested credential fields recursively redacted while keeping structure
    visible.
    """
    from .utils.redaction import REDACTED, sanitize

    if value is None:
        return None
    if key == "connect_proxy_password":
        return REDACTED
    if key == "elc_accounts":
        return sanitize(value, _field="elc_accounts")
    return value


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
    """Load and save the Config dataclass from JSON on disk.

    Concurrency contract (mirrors QueueManager): targeted mutations
    (`set`/`unset`) run under an instance mutex plus a cross-process file
    lock, reload the newest on-disk config first, apply only the requested
    change, and persist atomically via a unique fsync'd temp file. This
    prevents two CLI/EVdlc processes from losing each other's updates or
    colliding on a shared temp file.
    """

    def __init__(self, path: Path | None = None, lock_timeout: float = 10.0):
        self.path = path or config_file()
        self._config: Config | None = None
        self.lock_timeout = lock_timeout
        self._mutex = threading.RLock()
        self._file_lock = FileLock(
            self.path.parent / (self.path.name + ".lock"),
            message=(
                f"Could not lock the config file within {lock_timeout:.0f}s; "
                "another process is updating it. Retry shortly."
            ),
        )
        self._lock_depth = 0

    @contextlib.contextmanager
    def _locked(self):
        """Hold the instance mutex plus the cross-process file lock (once)."""
        self._mutex.acquire()
        try:
            if self._lock_depth == 0:
                try:
                    self._file_lock.acquire(timeout=self.lock_timeout)
                except FileLockError as exc:
                    raise ConfigLockError(str(exc)) from None
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
                if self._lock_depth == 0:
                    self._file_lock.release()
        finally:
            self._mutex.release()

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
                _warn_once(
                    key,
                    f"config: ignoring deprecated key {key} ({DEPRECATED_CONFIG_KEYS[key]}); "
                    "run `mb config migrate` to remove it",
                )
                continue
            if hasattr(cfg, key):
                setattr(cfg, key, value)
            else:
                _warn_once(key, f"config: ignoring unknown key {key}")
        validate_config(cfg)
        if cfg.user_agent == "MegaBasterd-CLI/1.0":
            # Old persisted default carried a hard-coded version; empty means
            # "derive from the installed package version".
            cfg.user_agent = ""
        if not cfg.download_path:
            cfg.download_path = str(default_download_dir())
        return cfg

    def save(self) -> None:
        with self._locked():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Serialize BEFORE touching the filesystem so a serialization
            # failure leaves the original file untouched.
            payload = json.dumps(asdict(self.config), indent=2)
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=self.path.name + ".",
                suffix=".tmp",
                delete=False,
            ) as tf:
                tf.write(payload)
                tf.flush()
                os.fsync(tf.fileno())
                tmp_path = tf.name
            for attempt in range(5):
                try:
                    os.replace(tmp_path, self.path)
                    break
                except PermissionError:
                    if attempt == 4:
                        raise
                    time.sleep(0.05 * (attempt + 1))

    def _is_nullable(self, key: str) -> bool:
        return key in _OPTIONAL_STR_KEYS

    def _coerce(self, key: str, value):
        """Turn a CLI string into the field's typed value; parse null/none."""
        if key in DEPRECATED_CONFIG_KEYS:
            raise ValueError(f"{key} is deprecated: {DEPRECATED_CONFIG_KEYS[key]}")
        if not hasattr(self.config, key):
            raise KeyError(f"Unknown config key: {key}")
        # Nullable fields: an explicit null/none unsets to JSON null; any other
        # string is kept verbatim (so "null-value" or a URL stays a string).
        if self._is_nullable(key) and isinstance(value, str):
            if value.strip().lower() in _NULL_TOKENS:
                return None
            return value
        current = getattr(self.config, key)
        if isinstance(current, bool):
            lowered = str(value).strip().lower()
            if lowered in ("1", "true", "yes", "y", "on"):
                return True
            if lowered in ("0", "false", "no", "n", "off"):
                return False
            raise ValueError("Expected a boolean value: true/false, yes/no, on/off, or 1/0")
        if isinstance(current, dict):
            parsed = json.loads(value)
            if not isinstance(parsed, dict):
                raise ValueError("Expected a JSON object")
            return parsed
        if isinstance(current, int):
            return int(value)
        if isinstance(current, float):
            return float(value)
        return value

    def set(self, key: str, value) -> None:
        with self._locked():
            self._config = self.load()  # reload newest before mutating
            typed = self._coerce(key, value)
            validate_config_value(key, typed)
            setattr(self._config, key, typed)
            self.save()

    def unset(self, key: str) -> None:
        """Reset a nullable field to JSON null (fails for non-nullable keys)."""
        with self._locked():
            self._config = self.load()
            if key in DEPRECATED_CONFIG_KEYS:
                raise ValueError(f"{key} is deprecated: {DEPRECATED_CONFIG_KEYS[key]}")
            if not hasattr(self._config, key):
                raise KeyError(f"Unknown config key: {key}")
            if not self._is_nullable(key):
                raise ValueError(
                    f"{key} is not a nullable field; use `config reset` to restore defaults"
                )
            setattr(self._config, key, None)
            self.save()

    def raw_keys(self) -> frozenset[str]:
        """Keys present in the persisted JSON file (empty when absent)."""
        if not self.path.exists():
            return frozenset()
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return frozenset()
        return frozenset(data.keys()) if isinstance(data, dict) else frozenset()

    def migrate(self) -> list[str]:
        """Normalize the persisted config: drop deprecated/unknown keys.

        Returns the removed keys so callers (and EVdlc) can report them.
        Values of known keys are validated/kept by the normal load path.
        """
        with self._locked():
            stale = sorted(
                key
                for key in self.raw_keys()
                if key in DEPRECATED_CONFIG_KEYS or not hasattr(Config(), key)
            )
            self._config = self.load()
            self.save()
            return stale

    def reset(self) -> None:
        with self._locked():
            self._config = Config()
            self._config.download_path = str(default_download_dir())
            self.save()
