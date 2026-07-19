# MegaBasterd CLI v1.2.0

Suggested tag: `v1.2.0`

## Summary

MegaBasterd CLI v1.2.0 is a logging and diagnostics release. It keeps the existing transfer behavior intact while making CLI log files more useful for debugging real user runs and safer to share after review.

## Added

- Richer CLI file logs with a stable run id, command name, process id, thread name, module, function, and line number on each record.
- Startup diagnostics that record the package version, working directory, Python executable, Python version, platform, redacted startup arguments, selected log file, config file, effective log level, and quiet/verbose state.
- DEBUG-level runtime path and non-secret configuration summaries to make support reports easier to diagnose.
- CLI shutdown timing so logs show when a process finishes and how long it ran.
- Launcher-to-CLI run id propagation so `launcher-*.log`, launcher transcript files, and `cli-*.log` from the same run can be correlated.
- Regression tests for contextual log file records and expanded redaction behavior.

## Changed

- Package version is now `1.2.0`.
- README and usage documentation now describe the expanded logging metadata and privacy behavior.
- Existing core transfer behavior is unchanged.

## Fixed

- Improved redaction for non-MEGA URLs that contain sensitive query parameters such as `token`, `password`, `api_key`, `sid`, or `session`.
- Improved redaction for session-like, cookie-like, passphrase, password, and token-like payload fields in structured log messages.

## Removed

No user-facing features were removed.

## Breaking Changes

No intentional breaking CLI changes are included.

## Requirements

- Python 3.10 or newer.
- PowerShell 5.1 or PowerShell 7+ for `Run.ps1`.
- Internet access for MEGA transfers and first-time dependency installation.

## Safety Notes

- Logs can contain local paths, filenames, runtime paths, and operational details. Sensitive arguments and token-like values are redacted where the logger handles them, but logs should still be treated as private.
- Downloads write files to disk and overwrite or resume existing destinations by default.
- Upload, import, share, rename, move, trash, and remove commands can modify real MEGA account data.

## Upgrade Notes

- Re-run `.\Run.ps1` or reinstall with `python -m pip install -e .` so the updated package metadata is active.
- Existing configuration files and transfer state files remain compatible.

## License and Attribution

This project is released under the MIT License.

MegaBasterd CLI - Copyright (c) 2026 Kiaro Sama  
Original author: Kiaro Sama  
GitHub: https://github.com/KiaroSama  
Original repository: https://github.com/KiaroSama/megabasterd-cli  
Licensed under the MIT License.
