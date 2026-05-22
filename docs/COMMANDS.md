# Command Reference

All commands can be run through the source launcher:

```powershell
.\Run.ps1 <command> [arguments] [options]
```

The same commands are available as `mb`, `mbcli`, and `megabasterd-cli` after
an editable/package install.

Global options:

| Option | Purpose |
| --- | --- |
| `-v`, `--verbose` | Increase logging verbosity. Use `-vv` for debug logs. |
| `-q`, `--quiet` | Suppress normal console output. Errors still print. |
| `--log-file`, `--no-log-file` | Override config-driven log file behavior for this run. |
| `-h`, `--help` | Show help. |
| `--version` | Show package version. |

When commands are run through `Run.ps1`, launcher and CLI logs are written to
`Logs/` automatically. Use `--no-log-file` only when you want to disable the
Python-side file log for a specific CLI invocation.

## Transfer Commands

### `download`

```powershell
.\Run.ps1 download [URL ...] [OPTIONS]
```

Downloads one or more MEGA links. It supports public file links, public folder
links, file-in-folder links, folder-in-folder links, legacy link formats,
password-protected links, `mega://enc`, `mega://fenc`, `mega://elc`, `.dlc`
input files, and MegaCrypter `mc://` links.

When `--output` is omitted, downloads go to `<project>\Output`. Folder and
file-in-folder downloads preserve the MEGA folder hierarchy under that output
directory.

| Option | Purpose |
| --- | --- |
| `-o`, `--output DIR` | Destination directory. |
| `-w`, `--workers N` | Parallel chunk workers per file. |
| `-P`, `--parallel N` | Number of files to download at once. |
| `-l`, `--limit KBPS` | Global download speed cap for this command. `0` means unlimited. |
| `-p`, `--password TEXT` | Password for protected links. |
| `--no-verify` | Skip final MAC verification. |
| `--rename NAME` | Local filename override for one-file downloads. |
| `--proxy URL` | HTTP/SOCKS proxy for this run. |
| `-i`, `--input-file PATH` | Read links from text, or decrypt a `.dlc` file. |
| `--elc-user TEXT` | ELC account user. |
| `--elc-api-key TEXT` | ELC API key. |

Examples:

```powershell
.\Run.ps1 download "https://mega.nz/file/ID#KEY" -o .\downloads
.\Run.ps1 download "https://mega.nz/folder/ID#KEY" -P 4
.\Run.ps1 download -i .\links.txt -l 4096
.\Run.ps1 download -i .\container.dlc
```

### `upload`

```powershell
.\Run.ps1 upload [PATH ...] [OPTIONS]
```

Uploads files or directories to a MEGA account stored in the encrypted account
vault.

| Option | Purpose |
| --- | --- |
| `-a`, `--account ID` | Account email or label. |
| `-w`, `--workers N` | Parallel chunk workers per file. |
| `-P`, `--parallel N` | Number of files to upload at once. |
| `-l`, `--limit KBPS` | Global upload speed cap for this command. `0` means unlimited. |
| `--rename NAME` | Remote filename override for a single file. |
| `--target HANDLE_OR_PATH` | Destination folder handle or path. |
| `--keep-structure` | Preserve local directory structure. |
| `--keep-going` | Continue directory uploads after item failures and print a warning summary. |
| `--auto-account` | Pick an account by available quota. |
| `--share` | Print a public link after upload. |
| `--share-password TEXT` | Create password-protected share links. |
| `--mfa-code CODE` | Two-factor code if required. |
| `--vault-passphrase TEXT` | Non-interactive vault unlock. |

Examples:

```powershell
.\Run.ps1 upload .\movie.mkv --account me@example.com
.\Run.ps1 upload .\Photos --keep-structure --target Backups
.\Run.ps1 upload .\secret.zip --share --share-password "open"
```

### `stream`

```powershell
.\Run.ps1 stream URL [OPTIONS]
```

Runs a local HTTP server that fetches encrypted MEGA ranges, decrypts them on
the fly, and serves media players through normal HTTP Range requests.

| Option | Purpose |
| --- | --- |
| `-p`, `--port N` | Local HTTP port. |
| `-H`, `--host HOST` | Bind address. |
| `--password TEXT` | Password for protected links. |
| `--proxy URL` | Upstream MEGA proxy. |
| `--elc-user TEXT` | ELC account user. |
| `--elc-api-key TEXT` | ELC API key. |

## Public Link Commands

### `info`

```powershell
.\Run.ps1 info URL [--password TEXT] [--elc-user TEXT] [--elc-api-key TEXT]
```

Shows public link metadata without downloading or logging into an account: type,
name, size, node count, and container details where available. No MFA code is
needed because this command uses public-link APIs.

### `share`

```powershell
.\Run.ps1 share TARGET [OPTIONS]
```

Creates or removes a public link for a node in your account.

| Option | Purpose |
| --- | --- |
| `--password TEXT` | Wrap the share URL in MEGA password-link format. |
| `--remove` | Remove the public link. |
| `-a`, `--account ID` | Account email or label. |
| `--vault-passphrase TEXT` | Non-interactive vault unlock. |

## Cloud Commands

These commands require a stored account.

| Command | Syntax | Purpose |
| --- | --- | --- |
| `ls` | `.\Run.ps1 ls [PATH] [--all]` | List files and folders. |
| `mkdir` | `.\Run.ps1 mkdir NAME [--parent PATH]` | Create a remote folder. |
| `rm` | `.\Run.ps1 rm TARGET [--yes]` | Move a node to trash. |
| `mv` | `.\Run.ps1 mv SOURCE DESTINATION` | Move a node into another folder. |
| `rename` | `.\Run.ps1 rename TARGET NEW_NAME` | Rename a node. |
| `search` | `.\Run.ps1 search PATTERN [--regex]` | Search remote filenames. |
| `import` | `.\Run.ps1 import SHARE_URL [--target HANDLE]` | Server-side import of a public folder share. |

Common options: `-a/--account` and `--vault-passphrase`.

Trash commands:

```powershell
.\Run.ps1 trash list
.\Run.ps1 trash empty --yes
```

## Account Commands

```powershell
.\Run.ps1 account list
.\Run.ps1 account add EMAIL [--label NAME] [--default] [--verify/--no-verify]
.\Run.ps1 account remove EMAIL_OR_LABEL
.\Run.ps1 account default EMAIL_OR_LABEL
.\Run.ps1 account info [EMAIL_OR_LABEL]
.\Run.ps1 account refresh-all
```

Account passwords are stored in the encrypted vault. The vault passphrase is
prompted interactively unless `--vault-passphrase` is provided.

## Queue Commands

```powershell
.\Run.ps1 queue list
.\Run.ps1 queue add-download URL [-o DIR] [-p PASSWORD]
.\Run.ps1 queue add-upload PATH [-a ACCOUNT]
.\Run.ps1 queue remove ID
.\Run.ps1 queue clear
.\Run.ps1 queue run [--vault-passphrase TEXT]
```

The queue is persisted as JSON under `<project>/User/Data/queue.json`.

## Proxy Commands

```powershell
.\Run.ps1 proxy list [--config-urls/--no-config-urls]
.\Run.ps1 proxy add URL [URL ...]
.\Run.ps1 proxy remove URL
.\Run.ps1 proxy clear
.\Run.ps1 proxy import PATH
.\Run.ps1 proxy fetch [--protocol http|socks4|socks5] [--source URL] [--limit N] [--timeout N]
.\Run.ps1 proxy serve [--port N] [--password TEXT] [--any-port]
```

`proxy serve` starts a local CONNECT proxy for MEGA traffic. `proxy fetch`
imports public proxy lists into the local pool.

## Crypter Commands

```powershell
.\Run.ps1 crypter encrypt SOURCE DESTINATION [--password TEXT] [--chunk-size-mb N]
.\Run.ps1 crypter decrypt SOURCE DESTINATION [--password TEXT]
.\Run.ps1 crypter make-link MEGA_URL [OPTIONS]
.\Run.ps1 crypter resolve MC_URL [--password TEXT]
.\Run.ps1 crypter elc-resolve ELC_URL [--user TEXT] [--api-key TEXT]
.\Run.ps1 crypter dlc-resolve PATH
```

`encrypt` and `decrypt` are local file operations. `make-link`, `resolve`,
`elc-resolve`, and `dlc-resolve` interoperate with supported container/link
formats.

`dlc-resolve` uses JDownloader's public DLC service endpoint, which is HTTP-only
upstream. The DLC master key is a known public constant, but the returned URLs
could be substituted by a hostile network.

## Local File Utility Commands

```powershell
.\Run.ps1 split SOURCE PART_SIZE_MB [-o DIR]
.\Run.ps1 merge ANY_PART [-o PATH] [--delete-parts] [--no-verify]
.\Run.ps1 thumbnail SOURCE DESTINATION
```

`split` writes numbered part files and SHA-1 metadata. `merge` verifies and
reconstructs the original file. `thumbnail` creates a 250x250 JPEG for supported
image files when Pillow is installed.

## Watch Command

```powershell
.\Run.ps1 watch [--interval SECONDS] [-o DIR] [--run]
```

Watches clipboard text and queues MEGA links as they appear.

## Config Commands

```powershell
.\Run.ps1 config show
.\Run.ps1 config get KEY
.\Run.ps1 config set KEY VALUE
.\Run.ps1 config reset
.\Run.ps1 config path
```

Use `config path` to see the exact config file used on the current machine.
