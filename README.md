# MegaBasterd CLI

MegaBasterd CLI is a script-first Python command-line tool for MEGA.nz
transfers, with a PowerShell launcher for direct source usage.

It provides a terminal workflow for downloading public MEGA files and folders,
uploading through stored accounts, inspecting links, streaming MEGA files over a
local HTTP server, managing a transfer queue, using proxy pools, and running
local helper tools such as split, merge, thumbnail, and file encryption.

This project is inspired by [tonikelope/megabasterd](https://github.com/tonikelope/megabasterd)
and is focused on CLI/source-script usage rather than a desktop GUI.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](#requirements)

## Features

- Interactive PowerShell launcher with colored menus and dependency checks.
- Public MEGA file and folder downloads.
- Folder downloads that preserve the MEGA folder hierarchy locally.
- Chunked, resumable transfers using `.mbstate` state files.
- Live Rich-based transfer progress with colored bars, speed, ETA, and totals.
- Multi-file parallel download support.
- Public file, folder, file-in-folder, folder-in-folder, and legacy MEGA links.
- Password-protected MEGA links.
- `mega://enc`, `mega://fenc`, `mega://elc`, `.dlc`, and `mc://` MegaCrypter link/container handling.
- MEGA account storage with encrypted local credential vaults.
- Cloud operations for account files: list, mkdir, remove, move, rename, search, trash, import, and share.
- Upload support for local files and folders.
- Smart proxy pool management, public proxy fetching, and local CONNECT proxy mode.
- Local HTTP streaming with Range request support.
- Persistent transfer queue and clipboard watcher.
- File split/merge helpers with SHA-1 verification.
- Local AES-256-GCM crypter for files.
- Windows Hashcash acceleration through the bundled PowerShell/.NET helper,
  with optional C helper source for building a native executable.
- Optional thumbnail generation for supported image files when Pillow is installed.

DLC container support uses JDownloader's public HTTP-only DLC service endpoint.
The DLC master key is a known public constant, but resolve DLC files only on
networks you trust because returned URLs could be substituted by a hostile
network.

## Requirements

- Python 3.9 or newer.
- PowerShell 5.1 or PowerShell 7+ for `Run.ps1`.
- Internet access for MEGA transfers and first-time dependency installation.

Python dependencies are listed in [requirements.txt](requirements.txt) and
[pyproject.toml](pyproject.toml):

- click
- rich
- requests
- pycryptodome
- tenacity
- cryptography
- colorama on Windows

## Installation

Clone the repository:

```powershell
git clone https://github.com/KiaroSama/megabasterd-cli.git
cd megabasterd-cli
```

Run the launcher:

```powershell
.\Run.ps1
```

On first run, the launcher checks Python and required modules. If dependencies
are missing, it asks whether to install them into the project environment. The
default answer is `Y`.

Optional editable install:

```powershell
python -m pip install -e .
mb --help
```

After installation, these console commands are available:

```text
mb
mbcli
megabasterd-cli
```

Optional Windows Hashcash native executable:

```powershell
.\tools\build_hashcash_windows.ps1
```

The CLI automatically tries `Bin\hashcash-solver-win64.exe` first when it
exists. On Windows source runs, it can also use the bundled
`tools\hashcash_solver_windows.ps1` helper. Set `MEGABASTERD_HASHCASH_NATIVE=0`
to force the pure-Python fallback. Advanced users can set
`MEGABASTERD_HASHCASH_SOLVER` to a custom executable path; that executable is
launched directly, so only point it at code you trust.

## Usage

Open the interactive launcher menu:

```powershell
.\Run.ps1
```

Run direct commands through the launcher:

```powershell
.\Run.ps1 --help
.\Run.ps1 info "https://mega.nz/folder/ID#KEY"
.\Run.ps1 download "https://mega.nz/file/ID#KEY"
.\Run.ps1 download "https://mega.nz/folder/ID#KEY" -o .\downloads
.\Run.ps1 upload .\archive.zip --account me@example.com
.\Run.ps1 stream "https://mega.nz/file/ID#KEY" --port 8080
```

Run the package directly:

```powershell
python -m megabasterd_cli --help
python -m megabasterd_cli download "https://mega.nz/file/ID#KEY"
```

Run installed commands:

```powershell
mb --help
mb download "https://mega.nz/file/ID#KEY"
```

## Main Commands

| Command | Purpose |
| --- | --- |
| `download` | Download public files, folders, containers, and link lists. |
| `upload` | Upload files or folders to an authenticated MEGA account. |
| `stream` | Serve a MEGA file through a local HTTP server. |
| `info` | Show public MEGA link metadata without downloading or logging in. |
| `share` | Create or remove public links for account-owned nodes. |
| `ls`, `mkdir`, `rm`, `mv`, `rename`, `search`, `trash`, `import` | Cloud filesystem operations. |
| `account` | Add, remove, list, set default, and refresh MEGA accounts. |
| `queue` | Manage and run the persistent transfer queue. |
| `proxy` | Manage proxy pools, fetch proxy lists, and run CONNECT proxy mode. |
| `crypter` | Encrypt/decrypt local files and resolve supported container links. |
| `split`, `merge`, `thumbnail` | Local file utilities. |
| `watch` | Watch the clipboard and queue copied MEGA links. |
| `config` | Show, set, reset, and locate configuration. |

Use command-specific help for exact options:

```powershell
.\Run.ps1 download --help
.\Run.ps1 upload --help
.\Run.ps1 config --help
```

## Usage Flow

1. Run `.\Run.ps1`.
2. Let the launcher verify Python dependencies.
3. Choose an interactive menu option or run a direct CLI command.
4. Configure accounts or settings when needed.
5. Download, upload, stream, queue, or manage MEGA content.
6. Review logs only when troubleshooting.

## Safety Notes

This tool can affect real user data.

- Downloads write files to disk. If a destination file already exists, the
  current behavior is to use the same path and overwrite or resume that file.
- Upload, import, share, rename, move, trash, and remove commands affect the
  configured MEGA account.
- `trash empty` permanently clears MEGA trash content.
- `rm` moves remote nodes to trash.
- `run_command` in the config runs a local command after successful transfers.
- Proxy features route traffic through configured or fetched proxies. Use only
  proxy sources you trust.
- Logs can contain local paths and operational details. Sensitive command
  arguments and MEGA links are redacted where the logger handles them, but logs
  should still be treated as private.
- Use this software only with content you are allowed to download, upload,
  import, stream, or share.

## Logs and Output

Default download output:

```text
<project>\Output
```

Project-local user data:

```text
<project>\User
```

Launcher logs:

```text
<project>\Logs
```

Typical generated files include:

| Path or pattern | Purpose |
| --- | --- |
| `Output/` | Default download destination. |
| `User/Config/config.json` | Local configuration. |
| `User/Data/accounts.json` | Encrypted account vault. |
| `User/Data/queue.json` | Transfer queue. |
| `User/Data/proxies.json` | Proxy pool. |
| `User/Data/sessions/` | Local session data. |
| `Logs/*.log` | Launcher and CLI logs. |
| `*.mbstate` | Resumable transfer state next to partial downloads. |

These paths are ignored by Git because they may contain private data or
generated output.

## Important Repository Files

| Path | Purpose |
| --- | --- |
| [Run.ps1](Run.ps1) | Main PowerShell launcher for source usage. |
| [pyproject.toml](pyproject.toml) | Python package metadata, dependencies, and tool config. |
| [requirements.txt](requirements.txt) | Runtime dependency list for launcher installation. |
| [src/megabasterd_cli/](src/megabasterd_cli/) | Main Python package. |
| [tests/](tests/) | Unit test suite. |
| [docs/](docs/) | Command, configuration, usage, and architecture documentation. |
| [.github/](.github/) | Issue templates and CI workflows. |
| [LICENSE](LICENSE) | MIT License. |
| [ATTRIBUTION.md](ATTRIBUTION.md) | Public attribution notice. |
| [CHANGELOG.md](CHANGELOG.md) | User-facing release history. |
| [GITHUB_RELEASE_NOTES.md](GITHUB_RELEASE_NOTES.md) | Draft notes for the next GitHub release. |

## Documentation

- [Usage guide](docs/USAGE.md)
- [Command reference](docs/COMMANDS.md)
- [Configuration reference](docs/CONFIG.md)
- [Architecture overview](docs/ARCHITECTURE.md)
- [Contributing guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Development

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
pytest
ruff check src tests
black --check src tests
```

The test suite is designed to run without real MEGA credentials.

## Troubleshooting

### The launcher closes immediately

Run it from an existing PowerShell window:

```powershell
.\Run.ps1
```

The launcher normally stays open after errors so the message can be read.

### Dependency installation fails

Check Python and pip:

```powershell
python --version
python -m pip --version
python -m pip install -r requirements.txt
```

Then run:

```powershell
.\Run.ps1 --help
```

### A download resumes unexpectedly

The downloader uses `.mbstate` files for resume support. Delete the partial
output file and its matching `.mbstate` file if you want a completely fresh
download.

### A download overwrites an existing file

That is the default behavior. Choose a different output directory or move the
existing file before starting the download if you need to keep both copies.

### MEGA quota is exceeded

The downloader waits according to `quota_wait_seconds` and retries up to
`quota_max_wait_loops`. These values can be changed with `config set`.

### MAC verification fails

Delete the partial output and `.mbstate` file, then retry. Repeated failures can
indicate unstable metadata or network issues.

### Cloud commands cannot find an account

Add an account or set the default account:

```powershell
.\Run.ps1 account add me@example.com --default
.\Run.ps1 config set default_account me@example.com
```

## Acknowledgements

MegaBasterd CLI is inspired by the original
[MegaBasterd](https://github.com/tonikelope/megabasterd) project by tonikelope.

## License and Attribution

This project is released under the MIT License.

You are free to use, copy, modify, publish, distribute, sublicense, and use this
project in your own projects, including free or commercial projects.

However, if you copy, modify, publish, distribute, or include substantial parts
of this project in another project, you must keep the original copyright and
license notice.

Please preserve this attribution:

MegaBasterd CLI - Copyright (c) 2026 Kiaro Sama  
Original author: Kiaro Sama  
GitHub: https://github.com/KiaroSama  
Original repository: https://github.com/KiaroSama/megabasterd-cli  
Licensed under the MIT License.

## Donate

If this project helps you, donations are appreciated.

| Currency | Network | Address |
| --- | --- | --- |
| Bitcoin (BTC) | Bitcoin | `bc1qmth5m03pu5hujw5xw5jmywam3jj3sqwqupesdt` |
| USDT, BNB, USDC, etc. | BEP20 | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |
| USDT, TRX, USDC, etc. | TRC20 | `TWBA3xFTqgZAeAYMxqo85xWnzvty3DcAhw` |
| Ethereum (ETH) | ERC20 | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |
| TON | TON | `UQCN8Umo_OfOWqImZetQsrNStPcmLkMAKajFyiCOhso23NDb` |
| Litecoin (LTC) | LTC | `ltc1qntqnnrunadurnw4cshv3qgspywrueyyeyngwuy` |
| Solana (SOL) | Solana | `7B2wkczUjmkDhETwQuknBL8sUsbuV7nErxc317TmQuwR` |
| Polygon (POL) | Polygon | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |
