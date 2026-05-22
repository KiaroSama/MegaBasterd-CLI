# MegaBasterd CLI v1.1.0

Suggested tag: `v1.1.0`

## Summary

MegaBasterd CLI v1.1.0 is a hardening and usability release for the
script-first MEGA.nz transfer CLI. It improves resume safety, session security,
streaming refresh behavior, folder upload handling, packaging metadata, and
Windows Hashcash support.

## Added

- Windows Hashcash acceleration support through the bundled PowerShell/.NET
  helper and optional native C helper source.
- `upload --keep-going` for directory uploads, allowing successful files to be
  kept when some items fail.
- Encrypted saved-session support using a passphrase-protected vault payload.
- Transfer state format versioning for safer future resume-state changes.
- Regression tests for session encryption, downloader resume validation,
  streaming refresh behavior, MegaCrypter handling, uploader keep-going mode,
  and state-file versioning.

## Changed

- Package version is now `1.1.0`.
- Upload resume state is stored under project user data instead of next to the
  source file.
- Download and upload speed-limit documentation now describes the actual global
  per-command behavior.
- Public `info` help text now clarifies that the command inspects public links
  without account login or MFA.
- Package data no longer includes Windows `.exe` helper artifacts.
- CONNECT proxy tunnel shutdown waits longer before closing paired sockets.

## Fixed

- Integrity verification now fails loudly when required chunk MAC data is
  missing.
- Download resume state is rejected when it does not match the source,
  destination, file size, key, nonce, or chunk map.
- CDN URL refresh no longer holds the main URL lock across network I/O.
- Streaming refresh now retries expired CDN URLs and preserves configured
  proxies for MegaCrypter refreshes.
- Upload URL expiry now retries once with clearer recovery guidance.
- Account-backed cloud, share, queue, and upload paths now support MFA prompts
  consistently where login is required.
- `import --target` now resolves target paths as well as handles.
- Boolean config values are parsed strictly instead of treating typos as false.
- Malformed MEGA attribute blobs return a safe `None` result instead of
  surfacing low-level crypto exceptions.
- Filename truncation preserves file extensions when possible.
- Modern MEGA links with trailing slashes are accepted.
- Startup logs redact additional sensitive arguments.

## Removed

- Removed the unused `tqdm` dependency.
- Removed dead downloader URL setter code.

## Breaking Changes

No intentional breaking CLI changes are included.

Saved sessions are now encrypted. Plaintext legacy session files are refused by
default unless `MEGABASTERD_ALLOW_PLAINTEXT_SESSION=1` is set explicitly.

## Requirements

- Python 3.9 or newer.
- PowerShell 5.1 or PowerShell 7+ for `Run.ps1`.
- Internet access for MEGA transfers and first-time dependency installation.

## Safety Notes

- Downloads write files to disk and overwrite or resume existing destinations
  by default.
- Upload, import, share, rename, move, trash, and remove commands can modify
  real MEGA account data.
- Logs can contain local paths and operational details. Sensitive arguments and
  MEGA links are redacted where the logger handles them, but logs should still
  be treated as private.
- DLC resolution uses JDownloader's public HTTP-only DLC service endpoint. The
  DLC master key is public, but returned URLs could be substituted on hostile
  networks.

## Upgrade Notes

- Re-run `.\Run.ps1` or reinstall with `python -m pip install -e .` so the
  updated package metadata and dependencies are active.
- If an upload resume state fails after a file was moved or renamed, start a
  fresh upload; upload state is keyed by local path and size.
- If a saved session no longer loads, log in again and save a new encrypted
  session with a passphrase.

## License and Attribution

This project is released under the MIT License.

MegaBasterd CLI - Copyright (c) 2026 Kiaro Sama  
Original author: Kiaro Sama  
GitHub: https://github.com/KiaroSama  
Original repository: https://github.com/KiaroSama/megabasterd-cli  
Licensed under the MIT License.
