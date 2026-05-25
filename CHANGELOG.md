# Changelog

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
