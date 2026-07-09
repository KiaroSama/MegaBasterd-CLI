# Changelog

## Unreleased

### Added
- Selective folder-link downloads (parity with the original MegaBasterd folder-link dialog): repeatable `--include`/`--exclude` glob filters over folder-relative paths, plus an interactive `--select` picker (`all` / `none` / `1,3-5`) on the `download` command.

### Fixed
- Fixed an intermittent deadlock between the folder-download live view and Rich's auto-refresh thread (lock-order inversion) that could freeze the progress UI and hang the CLI at completion.
- Fixed inflated download speeds at the start of resumed folder downloads: the live view no longer counts previously-downloaded bytes as instantaneous speed, and the overall speed is derived from the per-file meters (or a fresh backend hint) instead of a duplicate aggregate meter.

### Security
- Fixed a folder-download path-traversal weakness: remote node names can no longer become `.`, `..`, empty, or contain path separators, and every download destination is verified to stay inside the chosen output directory.
- Added MBCR v2 for the local file Crypter with authenticated chunk ordering, a final-chunk marker, original-length validation, and whole-file sequence integrity (detecting truncation, reordering, duplication, and tampering); legacy v1 files remain readable but do not provide whole-file sequence integrity.
- Required authentication for non-loopback streaming and made `Authorization: Bearer` the default token method; the token is generated automatically for non-loopback binds and is never written to logs.
- Prevented stream-token leakage from both the CLI startup argument log and the PowerShell launcher log and transcript.
- Switched DLC container resolution to HTTPS-only transport with bounded, manually validated redirects, same-origin enforcement, approved-origin validation, and rejection of credentials, non-global IPs, and unexpected ports.
- Encrypted persisted queue passwords at rest with AES-256-GCM under a locally stored key, and hardened queue-key creation, length validation, legacy migration, and recovery so existing encrypted secrets are never orphaned.
- Unified the local CONNECT proxy and plain-HTTP forward destination policy (host allow-list and port policy applied to both).
- Improved redaction of sensitive identifiers and command-line arguments (including account emails and stream tokens).

### Changed
- Downloads now preserve an existing unrelated file by default and write to a unique destination name (for example `name (1).ext`); a valid resumable partial still resumes.
- Added an explicit `--overwrite` (alias `--force`) option to `download` for in-place replacement.
- Stream query-string tokens (`?token=`) are disabled by default and require explicit opt-in via `--allow-query-token`.
- Documentation updated (README, command reference, usage guide) to match the hardened download, streaming, and DLC behavior.

### Testing
- Expanded regression coverage for path containment, Crypter tamper resistance, streaming authentication, queue-secret recovery, DLC redirect/SSRF behavior, resume safety, proxy destination policy, and launcher token redaction.
- Completed a live public-folder validation covering download, repeat-download/overwrite, resume, streaming with HTTP Range requests, and log redaction. Account login, upload, cloud mutations, MFA, DLC, ELC, and MegaCrypter end-to-end flows were not validated live.

## v1.2.0 - 2026-05-25

### Added
- Added richer CLI file logging with per-run identifiers, command context, process and thread details, source module/function/line metadata, runtime path details, non-secret configuration summaries, and shutdown timing.
- Added launcher-to-CLI run id propagation so launcher logs and CLI logs from the same run can be correlated.
- Added regression coverage for contextual log records and expanded redaction behavior.

### Changed
- Bumped the package version to `1.2.0`.
- Updated README and usage documentation to describe the expanded logging metadata and privacy behavior.

### Security
- Expanded log redaction for MEGA links, MegaCrypter links, API-style query secrets, session-like fields, cookie-like fields, passphrases, and token-like payload values.
- Logs still include local paths and operational details, so they should continue to be treated as private.

## v1.1.0 - 2026-05-22

### Added
- Added Windows Hashcash acceleration support with a bundled PowerShell/.NET helper and optional native C helper source.
- Added `upload --keep-going` for directory uploads so successful files can be kept when some items fail.
- Added encrypted session persistence with passphrase-protected session files.
- Added support for clearer live multi-file progress output during folder downloads.
- Added transfer state format versioning for safer future resume-state changes.

### Changed
- Bumped the package version to `1.1.0`.
- Clarified that download and upload speed limits are global caps for each command run.
- Moved upload resume state into project user data instead of writing it next to source files.
- Improved public `info` help text to clarify that it does not require account login or MFA.
- Updated packaging metadata to stop including Windows `.exe` helpers in source package data.
- Increased CONNECT proxy tunnel join timeout to reduce noisy tunnel shutdowns.

### Fixed
- Fixed integrity verification so missing chunk MACs fail loudly instead of silently passing.
- Fixed download resume validation to reject stale state from a different source, destination, or crypto context.
- Fixed CDN URL refresh locking for downloader workers.
- Fixed streaming CDN URL refresh and MegaCrypter proxy propagation.
- Fixed upload URL expiry handling with clearer recovery messages.
- Fixed cloud, share, queue, and upload paths to support MFA prompts consistently where account login is required.
- Fixed `import --target` path resolution.
- Fixed strict boolean config parsing.
- Fixed malformed MEGA attribute blobs so they return `None` instead of raising low-level crypto errors.
- Fixed filename truncation to preserve extensions when possible.
- Fixed legacy and modern link parsing edge cases, including trailing slashes on modern links.
- Fixed plaintext session loading to require explicit opt-in for old session files.

### Removed
- Removed the unused `tqdm` dependency.
- Removed dead downloader URL setter code.

### Security
- Encrypted saved sessions instead of writing SID, master key, and RSA private key in plaintext.
- Redacted additional sensitive CLI arguments from startup logs.
- Hardened CONNECT proxy password comparison and Windows socket binding.
- Added documentation warning for JDownloader DLC resolution through its HTTP-only upstream service.
