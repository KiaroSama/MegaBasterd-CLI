# MegaBasterd CLI v1.0.0

## Summary

MegaBasterd CLI v1.0.0 is the first public release of a script-first Python CLI
for MEGA.nz transfers, with a PowerShell launcher for direct source usage.

## Features

- Interactive PowerShell launcher with dependency checks.
- Public MEGA file and folder downloads.
- Folder downloads that preserve the MEGA folder hierarchy locally.
- Chunked, resumable transfers using `.mbstate` state files.
- Live Rich-based transfer progress with colored bars, speed, ETA, and totals.
- Multi-file parallel downloads.
- Upload support for stored MEGA accounts.
- Encrypted local account vault.
- Link metadata inspection.
- Local HTTP streaming with Range request support.
- Persistent transfer queue and clipboard watcher.
- Cloud operations for stored accounts: list, mkdir, remove, move, rename,
  search, trash, import, and share.
- Smart proxy pool management, public proxy fetching, and local CONNECT proxy
  mode.
- Local file tools: split, merge, thumbnail, and AES-256-GCM crypter.
- Support for public MEGA links, legacy link formats, password links,
  `mega://enc`, `mega://fenc`, `mega://elc`, `.dlc`, and `mc://` MegaCrypter
  links where applicable.

## Requirements

- Python 3.9 or newer.
- PowerShell 5.1 or PowerShell 7+ for `Run.ps1`.
- Internet access for first-time dependency installation and MEGA transfers.

## Safety Notes

- Downloads write files to disk and overwrite or resume existing destination
  files by default.
- Upload, import, share, rename, move, trash, and remove commands can modify
  real MEGA account data.
- `trash empty` clears MEGA trash content.
- `run_command` can execute local commands after successful transfers.
- Logs should be treated as private because they can include local paths and
  operational details.
- Use this software only with content you are allowed to download, upload,
  stream, import, or share.

## Installation and Quick Start

```powershell
git clone https://github.com/KiaroSama/megabasterd-cli.git
cd megabasterd-cli
.\Run.ps1
```

Direct command examples:

```powershell
.\Run.ps1 --help
.\Run.ps1 info "https://mega.nz/folder/ID#KEY"
.\Run.ps1 download "https://mega.nz/file/ID#KEY"
.\Run.ps1 download "https://mega.nz/folder/ID#KEY" -o .\downloads
```

Optional editable install:

```powershell
python -m pip install -e .
mb --help
```

## Included Files

- `Run.ps1` - source launcher.
- `src/megabasterd_cli/` - Python package.
- `requirements.txt` - runtime dependencies used by the launcher.
- `pyproject.toml` - package metadata and tooling config.
- `docs/` - usage, command, configuration, and architecture documentation.
- `tests/` - unit tests.
- `.github/` - issue templates and CI workflows.
- `README.md` - project overview and usage guide.
- `LICENSE` - MIT License.
- `ATTRIBUTION.md` - attribution notice.

## License

This project is released under the MIT License.

## Attribution

MegaBasterd CLI - Copyright (c) 2026 Kiaro Sama  
Original author: Kiaro Sama  
GitHub: https://github.com/KiaroSama  
Original repository: https://github.com/KiaroSama/megabasterd-cli  
Licensed under the MIT License.
