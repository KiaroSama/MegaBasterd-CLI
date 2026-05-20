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

## Transfer Settings

| Key | Default | Purpose |
| --- | --- | --- |
| `download_path` | `<project>\Output` | Default destination for downloads. |
| `max_workers` | `8` | Parallel chunk workers per downloaded file. |
| `upload_workers` | `4` | Parallel chunk workers per uploaded file. |
| `max_parallel_downloads` | `6` | Number of files downloaded at once. |
| `max_parallel_uploads` | `1` | Number of files uploaded at once. |
| `chunk_size_kb` | `1024` | Maximum MEGA chunk size. |
| `speed_limit_kbps` | `0` | Download cap in KB/s. `0` means unlimited. |
| `upload_speed_limit_kbps` | `0` | Upload cap in KB/s. `0` means unlimited. |
| `verify_integrity` | `true` | Verify final MAC after download. |
| `timeout_seconds` | `60` | HTTP timeout. |
| `auto_resume` | `true` | Reuse `.mbstate` files. |
| `keep_state_files_on_error` | `true` | Keep state files after failed transfers. |
| `quota_wait_seconds` | `3600` | Wait after quota errors. |
| `quota_max_wait_loops` | `24` | Maximum quota wait loops. |

## Account and Streaming Settings

| Key | Default | Purpose |
| --- | --- | --- |
| `default_account` | `null` | Account used when `--account` is omitted. |
| `streaming_port` | `8080` | Default port for `stream`. |
| `streaming_host` | `127.0.0.1` | Default stream bind host. |

## Proxy Settings

| Key | Default | Purpose |
| --- | --- | --- |
| `smart_proxy_enabled` | `false` | Enable rotating proxy pool. |
| `smart_proxy_url` | `null` | One proxy URL or a comma-separated URL list. |
| `force_smart_proxy` | `false` | Refuse direct connections. |
| `smart_proxy_autorefresh_minutes` | `0` | Refetch proxy list every N minutes. |
| `smart_proxy_timeout_seconds` | `10` | Timeout per proxy connection. |
| `smart_proxy_random` | `true` | Random selection instead of round-robin. |

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
| `user_agent` | `MegaBasterd-CLI/1.0` | HTTP user agent. |
| `run_command` | `null` | Command run after each completed transfer. |
| `upload_log_path` | `null` | JSON-lines upload log path. |

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
