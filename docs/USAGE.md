# MegaBasterd CLI Usage Guide

This guide explains how to run the project directly from source, how transfers
work, how configuration is stored, and how common workflows fit together.

For every command and option, see [COMMANDS.md](COMMANDS.md).

## 1. Running From Source

The primary entry point is the PowerShell launcher in the project root:

```powershell
.\Run.ps1
```

On the first run, the launcher checks required Python modules. If anything is
missing, it prompts:

```text
Install dependencies now into the project environment? (y/n) [Y]:
```

Press Enter or type `y` to install. The launcher creates `.venv` when needed,
installs `requirements.txt`, adds `src/` to `PYTHONPATH`, and then opens the
interactive menu. The menu covers download, info, upload, account/cloud
operations, queue/proxy tools, local tools, and settings.

Direct command usage still runs:

```powershell
python -m megabasterd_cli <your arguments>
```

No build step is needed.

## 2. Basic Examples

```powershell
# Show help
.\Run.ps1 --help

# Inspect a public folder
.\Run.ps1 info "https://mega.nz/folder/ID#KEY"

# Download a public file
.\Run.ps1 download "https://mega.nz/file/ID#KEY" -o .\downloads

# Download to the default Output directory
.\Run.ps1 download "https://mega.nz/folder/ID#KEY"

# Download a file list
.\Run.ps1 download -i .\links.txt -o .\downloads -P 4

# Stream a file locally
.\Run.ps1 stream "https://mega.nz/file/ID#KEY" --port 8080

# Add an account
.\Run.ps1 account add me@example.com --default

# Upload and create a public link
.\Run.ps1 upload .\archive.zip --share
```

`info` inspects public links only and does not log into a MEGA account, so it
does not need MFA options.

If the package is installed with `python -m pip install -e .`, the same commands
can be run as `mb`, `mbcli`, or `megabasterd-cli`.

## 3. Supported Link Types

The parser and transfer layer support:

| Type | Example |
| --- | --- |
| Public file | `https://mega.nz/file/FILE#KEY` |
| Public folder | `https://mega.nz/folder/FOLDER#KEY` |
| File in folder | `https://mega.nz/folder/FOLDER#KEY/file/FILE` |
| Folder in folder | `https://mega.nz/folder/FOLDER#KEY/folder/SUBFOLDER` |
| Legacy file | `https://mega.nz/#!FILE!KEY` |
| Legacy folder | `https://mega.nz/#F!FOLDER!KEY` |
| Legacy folder file | `https://mega.nz/#F!FOLDER!KEY!FILE` |
| Legacy compact folder file | `https://mega.nz/#F*FILE!FOLDER!KEY` |
| Legacy node link | `https://mega.nz/#N!FILE!FOLDER!KEY` |
| Password link | `https://mega.nz/#P!...` |
| Encrypted container | `mega://enc?...` and `mega://fenc?...` |
| ELC container | `mega://elc?...` |
| DLC file | `.\Run.ps1 download -i .\container.dlc` |
| MegaCrypter | `mc://...` |

DLC containers are resolved through JDownloader's public DLC service endpoint
over HTTPS, following redirects only within that same trusted origin. The DLC
master key is a known public constant, so this does not protect or expose a
secret key, but the returned URLs come from that third-party service. Resolve
DLC files only on networks you trust.

## 4. Download Behavior

Downloads are chunked and resumable.

```powershell
.\Run.ps1 download URL -o .\downloads -w 8 -P 3 -l 4096
```

If `-o/--output` is omitted, files are saved to:

```text
<project>\Output
```

Public folder downloads preserve MEGA's folder tree. For example, a MEGA share
that contains `Root/Season 01/Episode 01.mkv` is saved as
`Output/Root/Season 01/Episode 01.mkv`. File-in-folder links also keep their
folder ancestry instead of being flattened into the output root.

If a destination file already exists and is not a resumable partial of the same
transfer, the download is written to a unique name (for example `name (1).ext`)
so the existing file is preserved. Pass `--overwrite` (alias `--force`) to
replace the existing file in place. A valid `.mbstate` partial still resumes.

Important flags:

| Flag | Meaning |
| --- | --- |
| `-w`, `--workers` | Chunk workers per file. |
| `-P`, `--parallel` | Number of files downloading at once. |
| `-l`, `--limit` | Global download speed cap in KB/s for this command. |
| `--no-verify` | Skip final MAC verification. |
| `--overwrite`, `--force` | Replace an existing destination instead of using a unique name. |
| `--proxy` | Proxy URL for this run. |
| `--password` | Password for protected links. |
| `--elc-user`, `--elc-api-key` | Credentials for ELC resolution. |

Each partial download writes a `.mbstate` file next to the output. Re-running
the same command resumes missing chunks. If final integrity verification fails,
the state file is kept for investigation.

### Windows Hashcash acceleration

When MEGA returns an API Hashcash challenge, the CLI solves it before retrying
the request. On Windows source runs, the CLI automatically tries the bundled
PowerShell/.NET helper and falls back to pure Python if no helper is available.

To build the optional native executable:

```powershell
.\tools\build_hashcash_windows.ps1
```

The generated helper is expected at:

```text
Bin\hashcash-solver-win64.exe
```

Set `MEGABASTERD_HASHCASH_NATIVE=0` to disable helper use for troubleshooting.
Advanced users can set `MEGABASTERD_HASHCASH_SOLVER` to a custom executable
path. The CLI runs that executable directly, so only use a solver you trust.

## 5. Upload Behavior

Uploads require a stored MEGA account:

```powershell
.\Run.ps1 account add me@example.com
.\Run.ps1 upload .\file.zip --account me@example.com
```

Useful upload modes:

```powershell
# Preserve a directory tree
.\Run.ps1 upload .\Photos --keep-structure --target Backups

# Keep uploading the rest of a directory when one item fails
.\Run.ps1 upload .\Photos --keep-structure --keep-going

# Pick account by free quota
.\Run.ps1 upload .\LargeFiles --auto-account

# Create a share link after upload
.\Run.ps1 upload .\report.pdf --share

# Create a password-protected share link
.\Run.ps1 upload .\private.zip --share --share-password "secret"
```

Upload resume state is stored under `<project>\User\Data\upload-state`. It is
keyed by the local file path and size, so moving or renaming a source file starts
a fresh upload state.

## 6. Accounts and Vault

Account passwords are stored encrypted with AES-GCM. The vault key is derived
from your vault passphrase with scrypt.

```powershell
.\Run.ps1 account list
.\Run.ps1 account add me@example.com --label main --default
.\Run.ps1 account info main
.\Run.ps1 account refresh-all
.\Run.ps1 account remove main
```

For non-interactive scripts, pass `--vault-passphrase`. Avoid putting secrets in
shell history unless the environment is controlled.

## 7. Cloud Operations

```powershell
.\Run.ps1 ls
.\Run.ps1 ls Backups --all
.\Run.ps1 mkdir "Camera Roll" --parent Backups
.\Run.ps1 search "invoice"
.\Run.ps1 rename "old.txt" "new.txt"
.\Run.ps1 mv "new.txt" Documents
.\Run.ps1 rm "new.txt" --yes
.\Run.ps1 trash list
.\Run.ps1 trash empty --yes
```

Public folder import copies nodes server-side into your account:

```powershell
.\Run.ps1 import "https://mega.nz/folder/ID#KEY" --target Backups
```

## 8. Streaming

Streaming resolves the file once, asks MEGA for a CDN URL, and serves decrypted
ranges locally:

```powershell
.\Run.ps1 stream "https://mega.nz/file/ID#KEY" --port 8080
```

Open this in VLC, mpv, or a browser:

```text
http://127.0.0.1:8080/
```

The stream server supports HTTP Range requests, so seeking works without a full
download.

A loopback bind (the default `127.0.0.1`) runs without authentication. If you
bind a non-loopback host, access requires a token sent as
`Authorization: Bearer <token>`; when you do not pass `--token`, one is
generated and printed once on the console (never written to logs). Query-string
tokens (`?token=`) are disabled unless you add `--allow-query-token`.

## 9. Smart Proxy

```powershell
.\Run.ps1 proxy fetch --protocol socks5 --limit 100
.\Run.ps1 proxy list
.\Run.ps1 config set smart_proxy_enabled true
```

To force all MEGA traffic through proxies:

```powershell
.\Run.ps1 config set force_smart_proxy true
```

To expose a local CONNECT proxy for another app:

```powershell
.\Run.ps1 proxy serve --port 9999 --password "secret"
```

## 10. Queue and Watcher

```powershell
.\Run.ps1 queue add-download "https://mega.nz/file/ID#KEY" -o .\downloads
.\Run.ps1 queue add-upload .\file.zip --account main
.\Run.ps1 queue list
.\Run.ps1 queue run
```

Clipboard watcher:

```powershell
.\Run.ps1 watch -o .\inbox
```

When a MEGA link is copied to the clipboard, it is added to the queue.

## 11. Local Crypter and Containers

Local encryption:

```powershell
.\Run.ps1 crypter encrypt .\secret.zip .\secret.zip.mbcr --password "pw"
.\Run.ps1 crypter decrypt .\secret.zip.mbcr .\secret.zip --password "pw"
```

Container/link helpers:

```powershell
.\Run.ps1 crypter resolve "mc://..."
.\Run.ps1 crypter elc-resolve "mega://elc?..."
.\Run.ps1 crypter dlc-resolve .\container.dlc
```

## 12. File Utilities

```powershell
.\Run.ps1 split .\large.iso 500 -o .\parts
.\Run.ps1 merge .\parts\large.iso.part1-10 -o .\large.iso
.\Run.ps1 thumbnail .\image.png .\thumb.jpg
```

`split` and `merge` include SHA-1 metadata so merged files can be verified.

## 13. Configuration

See the active config path:

```powershell
.\Run.ps1 config path
```

Show and edit settings:

```powershell
.\Run.ps1 config show
.\Run.ps1 config get download_path
.\Run.ps1 config set max_workers 8
.\Run.ps1 config reset
```

Common keys:

| Key | Purpose |
| --- | --- |
| `download_path` | Default download directory. |
| `max_workers` | Chunk workers per download. |
| `max_parallel_downloads` | Files downloaded at once. |
| `upload_workers` | Chunk workers per upload. |
| `max_parallel_uploads` | Files uploaded at once. |
| `speed_limit_kbps` | Aggregate download cap for one command (shared by all parallel workers). |
| `upload_speed_limit_kbps` | Aggregate upload cap for one command. |
| `default_account` | Legacy fallback when `--account` is omitted and no vault default (`account default`) is set. |
| `smart_proxy_enabled` | Enable proxy pool. |
| `force_smart_proxy` | Refuse direct connections when no proxy is available. |
| `quota_wait_seconds` | Wait after MEGA quota errors. |
| `quota_max_wait_loops` | Max quota wait loops. |
| `streaming_port` | Default streaming port. |
| `streaming_host` | Default streaming bind address. |
| `run_command` | Post-transfer hook. |
| `upload_log_path` | JSON-lines upload log path. |

## 14. Launcher Environment Variables

| Variable | Purpose |
| --- | --- |
| `MEGABASTERD_PYTHON` | Force a specific Python interpreter. |
| `MEGABASTERD_AUTO_INSTALL=0` | Decline dependency installation automatically. |
| `MEGABASTERD_USER_DIR` | Override the project-local `User/` directory. |
| `MEGABASTERD_NO_PAUSE=1` | Disable the safety pause after direct command errors. |
| `NO_COLOR=1` | Disable launcher color output. |

## 15. Logging

`Run.ps1` writes logs on every run:

```text
Logs/launcher-<timestamp>.log
Logs/launcher-transcript-<timestamp>.log
Logs/cli-<timestamp>.log
```

The launcher log records dependency checks, selected Python, command dispatch,
exit code, and any launcher exception. The transcript captures the visible
PowerShell session. The CLI log records DEBUG-level Python details with run id,
command name, process/thread/function/line metadata, startup arguments after
redaction, runtime paths, a non-secret configuration summary, and shutdown
timing. Passwords, MFA codes, API keys, MEGA/MegaCrypter links, API-style query
secrets, session-like fields, and token-like payload values are redacted where
the logger handles them.

Useful logging config keys:

| Key | Purpose |
| --- | --- |
| `log_level` | Console log level when `-v/-vv` is not used. |
| `log_to_file` | Enable Python file logging outside the launcher path. |
| `log_max_bytes` | Maximum Python log file size before rotation. |
| `log_backups` | Number of rotated Python logs to retain. |

## 16. Troubleshooting

### Dependency install fails

Check that Python 3.9+ is installed and that the shell has internet access.
Then run:

```powershell
python -m pip install -r requirements.txt
.\Run.ps1 --help
```

### MEGA quota exceeded

The downloader waits for `quota_wait_seconds` and retries up to
`quota_max_wait_loops`. You can lower the wait loop count or switch to proxy
mode if the quota is IP-based.

### MAC verification failed

Delete the partial output and its `.mbstate` file, then retry. Repeated failures
usually mean the share metadata or network path is unstable.

### Cloud command says no account is configured

Add an account or set the default account:

```powershell
.\Run.ps1 account add me@example.com --default
.\Run.ps1 config set default_account me@example.com
```

### Clipboard watcher does not detect links

Install `pyperclip` or make sure your OS clipboard command is available:
PowerShell `Get-Clipboard` on Windows, `pbpaste` on macOS, or `wl-paste`/`xclip`
on Linux. (Windows and Linux are the CI-tested platforms; the macOS path exists
in the code but is untested.)

## 17. Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Fatal error or dependency setup failure. |
| `130` | Interrupted with Ctrl+C. |
