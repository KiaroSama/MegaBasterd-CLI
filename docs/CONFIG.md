# Configuration Reference

Configuration is stored as JSON under the project-local `User/` directory.
The exact path can always be printed with:

```powershell
.\Run.ps1 config path
```

## Editing

```powershell
.\Run.ps1 config show
.\Run.ps1 config get KEY
.\Run.ps1 config set KEY VALUE
.\Run.ps1 config reset
```

Values are cast to the field type defined by the application config dataclass.
Booleans accept `true`, `false`, `1`, `0`, `yes`, `no`, `on`, and `off`.

Values are validated centrally: `config set` rejects out-of-range values
(ports outside 1–65535, non-positive timeouts, worker counts outside 1–64,
negative speed limits or quota waits, unknown log levels) and exits non-zero,
and invalid values found in a hand-edited `config.json` produce a warning and
fall back to the default instead of crashing at runtime. Optional (nullable)
keys are type-checked too: `default_account`, `smart_proxy_url`,
`run_command`, `upload_log_path`, `connect_proxy_password`, and
`megacrypter_server` must be strings or null, and `elc_accounts` must be
`{host: {field: string}}`. Booleans are not accepted for numeric keys.

Secrets are never displayed: `config show` and `config get` print
`<redacted>` for `connect_proxy_password` and recursively redact the
credential fields inside `elc_accounts`; `config set` confirms only that the
key was updated and never echoes the value; validation warnings never echo
secret values.

Nullable keys can be cleared: `config set <key> null` (or `none`) stores JSON
null, and `mb config unset <key>` clears a nullable key (any other string
value, including a URL or the literal `null-value`, is kept verbatim).
`config get`/`set`/`unset` exit non-zero on unknown keys, invalid values, or
deprecated keys. Config writes are cross-process safe (a bounded file lock,
reload-before-write, and a unique fsync'd temp file), so the CLI and any
external caller can update the file concurrently without losing each other's
changes.

Deprecated or unknown keys in old files are ignored with a single warning per
key per process; `mb config migrate` rewrites the file without them.

## Corrupt config files

A `config.json` that is not valid UTF-8 JSON, or whose root is not an object,
is treated as corruption rather than silently replaced by defaults. The
original is preserved byte-for-byte and copied to
`config.json.corrupt.<timestamp>-<hash>.json`. Backups are deduplicated by
content, so re-reading the same broken file does not pile up copies while a
LATER, different corruption still gets its own backup; `set`, `unset`, `migrate`, and `reset`
then refuse with a sanitized message and a non-zero exit. `mb config recover`
reports the state, and `mb config recover --reset` writes a fresh default
config while keeping the backup. Corruption messages never include values read
from the corrupt file.

## Transfer Settings

| Key | Default | Purpose |
| --- | --- | --- |
| `download_path` | `<project>\Output` | Default destination for downloads. |
| `max_workers` | `8` | Parallel chunk workers per downloaded file. |
| `upload_workers` | `4` | Parallel chunk workers per uploaded file. |
| `max_parallel_downloads` | `6` | Number of files downloaded at once. |
| `max_parallel_uploads` | `1` | Number of files uploaded at once. |
| `speed_limit_kbps` | `0` | Aggregate download cap in KB/s for the whole command; every parallel worker shares one limiter. `0` means unlimited. |
| `upload_speed_limit_kbps` | `0` | Aggregate upload cap in KB/s for the whole command. `0` means unlimited. |
| `verify_integrity` | `true` | Verify final MAC after download. |
| `timeout_seconds` | `60` | HTTP timeout. |
| `auto_resume` | `true` | Reuse `.mbstate` files. When `false`, existing resume state is never reused for downloads or uploads (unrelated existing files are still preserved via unique names). |
| `keep_state_files_on_error` | `true` | Keep state files after failed transfers. |
| `quota_wait_seconds` | `3600` | Wait after quota errors. |
| `quota_max_wait_loops` | `24` | Maximum quota wait loops. |

## Account and Streaming Settings

| Key | Default | Purpose |
| --- | --- | --- |
| `default_account` | `null` | Legacy fallback account used when `--account` is omitted AND no vault default is set. Precedence everywhere (upload, queue, share, cloud): `--account` → `mb account default` (vault) → this key. |
| `streaming_port` | `8080` | Default port for `stream` (1–65535). |
| `streaming_host` | `127.0.0.1` | Default stream bind host. |

## Proxy Settings

| Key | Default | Purpose |
| --- | --- | --- |
| `smart_proxy_enabled` | `false` | Enable rotating proxy pool. |
| `smart_proxy_url` | `null` | One proxy URL or a comma-separated URL list. |
| `force_smart_proxy` | `false` | Refuse direct connections. Enforced on EVERY outbound request - API calls, chunk transfers, streaming CDN reads, MegaCrypter/DLC/ELC resolution, and `proxy fetch` - and the refusal happens before a socket is opened, with no direct fallback after a proxy failure. |

### Deprecated keys

These keys never had an effect and were removed; `config set` rejects them
with an explanation and old config files that still contain them load fine
(the keys are ignored with a warning):

| Key | Reason |
| --- | --- |
| `chunk_size_kb` | MEGA chunk sizes are protocol-defined and cannot be configured. |
| `smart_proxy_autorefresh_minutes` | Not implemented; the pool is reloaded on every command run. |
| `smart_proxy_timeout_seconds` | Not implemented; use `mb proxy fetch --timeout`. |
| `smart_proxy_random` | Not implemented; the pool always picks randomly, weighted by health. |

## CONNECT Proxy Settings

| Key | Default | Purpose |
| --- | --- | --- |
| `connect_proxy_port` | `9999` | Local CONNECT proxy port. |
| `connect_proxy_password` | `null` | Basic-Auth password for clients. |
| `connect_proxy_allow_any_port` | `false` | Allow CONNECT ports other than 443. |

## Container and Link Settings

| Key | Default | Purpose |
| --- | --- | --- |
| `megacrypter_server` | `null` | Default MegaCrypter server for `crypter make-link`. |
| `elc_accounts` | `{}` | Optional stored ELC account credentials by user. |

`elc_accounts` is a JSON object when set through `config set`:

```powershell
.\Run.ps1 config set elc_accounts '{ "example-elc-host.com": { "user": "user@example.com", "api_key": "API_KEY" } }'
```

You can avoid storing ELC credentials by passing `--elc-user` and
`--elc-api-key` directly to `download`, `info`, `stream`, or
`crypter elc-resolve`.

## Logging and Hooks

| Key | Default | Purpose |
| --- | --- | --- |
| `log_level` | `WARNING` | Default console log level; file logs still keep debug details. |
| `log_to_file` | `true` | Write debug logs to a file. |
| `log_max_bytes` | `5000000` | Rotate Python logs after this many bytes. |
| `log_backups` | `5` | Keep this many rotated Python log files. |
| `user_agent` | `""` | HTTP user agent for API and transfer requests. Empty means `MegaBasterd-CLI/<installed version>`. |
| `run_command` | `null` | Command run after each completed transfer. Parsed with Windows rules on Windows and POSIX rules elsewhere; the transferred path is appended as exactly one argument. Hook arguments are not written to logs. |
| `upload_log_path` | `null` | JSON-lines upload log path (written by every upload mode, including queue and directory uploads). |

## Runtime Data

| Data | Location |
| --- | --- |
| Config | `<project>/User/Config/config.json`, also printed by `.\Run.ps1 config path`. |
| Accounts vault | `<project>/User/Data/accounts.json`. |
| Sessions | `<project>/User/Data/sessions/`. |
| Queue | `<project>/User/Data/queue.json`. |
| Proxy pool | `<project>/User/Data/proxies.json`. |
| Resume state | Next to each transfer as `.mbstate`. |
| Launcher logs | `<project>/Logs/launcher-<timestamp>.log`. |
| Launcher transcripts | `<project>/Logs/launcher-transcript-<timestamp>.log`. |
| CLI logs | `<project>/Logs/cli-<timestamp>.log` through `Run.ps1`; user log directory when installed directly. |

## Per-Run Overrides

Most frequently edited settings have matching CLI options:

```powershell
.\Run.ps1 download URL -w 12 -P 4 -l 8192
.\Run.ps1 upload .\file.zip -w 8 -P 2
.\Run.ps1 stream URL --host 127.0.0.1 --port 9090
```

Command-line options affect only that invocation; config changes persist.

The source launcher sets the project root before running the CLI, so the default
source checkout destination is:

```text
<project>\Output
```
