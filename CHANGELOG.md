# Changelog

## Unreleased

### Security (deep audit rounds)
- Closed an SSRF in ELC and MegaCrypter link resolution: the service URL comes from the untrusted link, and although the initial URL was validated, redirects were followed automatically, so a hostile host could answer `307` and have the credential body (ELC user/API key, or the MegaCrypter link password and session) re-POSTed to loopback, link-local, or RFC1918 addresses. Every hop is now validated with automatic redirects disabled, matching the DLC path.
- The MegaCrypter host-supplied download URL is now validated (HTTPS-only, no userinfo, globally-routable host) before any fetcher connects to it, for both `download` and `stream`.
- Integrity verification now re-computes the file MAC from the bytes on disk instead of from the per-chunk MACs stored in the resume state, so a resumed file whose contents no longer match — a destination replaced between runs, or a silent disk write fault — fails verification instead of reporting success. A missing or truncated file fails closed.
- A resume state is reused only when it records the exact decryption key of the current transfer; a state that omits or mismatches the key is refused rather than trusted, and a state written by a newer format version is left intact and refused instead of being deleted.
- The MegaCrypter password-hashing iteration count from a hostile host is bounded before the exponent is materialized, so a crafted descriptor can no longer force a multi-gigabyte allocation.
- Exception tracebacks printed to the console are now redacted the same way as the log file, so a secret inside an error can no longer reach the terminal in cleartext; diagnostics and Rich tracebacks go to stderr so `--json` stdout stays valid JSONL.
- `config show`/`get` now redact any credential-bearing value (proxy URLs with `user:pass@`, authorization headers), and `proxy list`/`remove` redact schemeless proxy credentials that previously printed in full.
- Link keys are validated strictly: a key with characters outside unpadded URL-safe base64 (commas, whitespace) or the wrong decoded length is rejected with a clear message instead of being silently truncated or reshaped into a different key.
- `config show` and `proxy list` render untrusted values as plain text, so a stored config value or a fetched/imported proxy entry containing Rich markup can no longer restyle the output or crash the command.

### Fixed (deep audit rounds)
- A discarded or unusable resume state could leave a stale high revision on disk that silently blocked every save of the replacement transfer, so a long download persisted no resume state and an interruption lost all progress; the leftover is now cleared and an unreadable-as-state file no longer constrains saves.
- Fixed corrupt output when streaming a byte range whose start is not block-aligned and the first upstream block is shorter than the alignment skip: the served data is no longer shifted backward, and a short response is reported instead of silently truncated.
- The launcher now survives Windows PowerShell 5.1: the Python-interpreter probe and the pip/ensurepip step no longer abort on a candidate's stderr (the Microsoft Store `python3` alias, a conda/venv banner, or a `pip` warning), so the `py → python3 → python` fallback and the pip recovery both work on that host. A CI job now smoke-tests the launcher under 5.1.
- `account add` and machine-mode (`--json`) commands no longer hang forever waiting on a hidden password prompt with closed/redirected stdin; they fail with a message telling you to pass `--password`/`--vault-passphrase`.
- `account add` with the wrong vault passphrase no longer mixes credentials encrypted under two different passphrases into one vault: the passphrase is verified against an existing credential before anything is added.
- A wrong vault passphrase now reports a clear message instead of an empty `Error:` line under a raw decryption traceback.
- `proxy fetch` and `proxy serve` now exit non-zero when they fail, so a wrapper script can detect the failure.
- A link-service proxy is credited only after the response body is proven usable and blamed when the request fails, so a captive portal or dead proxy no longer climbs the pool's success ranking; rejected streamed responses are closed instead of stranding the connection.
- The launcher no longer leaves the tail of a quoted secret (`--password "…"`, `--token "…"`, etc.) unredacted in its log, and no longer creates a stray `Data\sessions` directory on non-Windows CI runs.

### Removed
- Dropped the declared `colorama` dependency: nothing in the project imports it, and `click` already pulls it in transitively on Windows.

### Added
- `mb config unset <key>` clears a nullable setting to JSON null; `config set <key> null|none` also stores null while any other string (including a URL or the literal `null-value`) is kept verbatim.
- `mb queue reset` recovers from a corrupt queue by writing a fresh empty one (the corrupt original is preserved as `queue.json.corrupt.<timestamp>.json`).
- Machine-mode failure records now carry a stable `error_code` plus sanitized identifying fields (`name`, `path`, redacted `source`, `account`).

### Fixed
- Machine (`--json`) output is now thread-safe: each JSONL record is sanitized and written as one atomic line under a lock, so parallel `-P N` download/upload output can never interleave into corrupt JSON. Every emitted value is passed through a central recursive secret sanitizer (MEGA link keys, SIDs, passwords, vault passphrases, MFA codes, ELC/API keys, proxy passwords, and secret query params — including inside `str(exc)` and nested structures); intentional `share_link` output keeps its public key.
- `--auto-account` now runs truly in parallel for flat files with `-P N` (previously it silently downgraded to sequential): each transfer gets its own isolated `MegaAPIClient`/HTTP session, accounts log in once (no repeated MFA), the free-space ledger and account store are thread-safe, and quota-error re-planning is bounded per account.
- The uploader resets all per-file state (`_stop_event`, byte/chunk counters, completion token, speed meter) at the start of every `upload_file`, so a failed or canceled file under `upload_directory(keep_going=True)` no longer poisons the next file (which previously aborted with "canceled while hashing").
- `config show`/`get` redact `connect_proxy_password` and the nested `elc_accounts` credentials; `config set` never echoes the value; `config get`/`set`/`unset` exit non-zero on unknown keys, invalid values, and deprecated keys.
- `ConfigStore` writes are now concurrent-safe (shared cross-process file lock, reload-before-write, unique fsync'd temp file), sharing the lock utility with `QueueManager`; the account vault save also uses a unique fsync'd temp file so parallel `--auto-account` quota refreshes cannot collide.
- A malformed or invalid-schema `queue.json` (non-list root, non-object entries, missing required fields, unknown type/status, wrong field types) is treated as corruption: the original is preserved byte-for-byte and backed up once, mutations are blocked with a non-zero exit and a clear message, and no queue key is created while integrity is unknown.
- API/HTTP sessions are closed on every failed-login path in normal and queued uploads (no leaked sessions/descriptors), and successful cached clients close exactly once.

### Changed
- An unknown job type/status in the queue file is now a schema violation (corruption) rather than a silently-run item.

### Added (progress, resume, queue, config — earlier audit rounds)
- Selective folder-link downloads (parity with the original MegaBasterd folder-link dialog): repeatable `--include`/`--exclude` glob filters over folder-relative paths, plus an interactive `--select` picker (`all` / `none` / `1,3-5`) on the `download` command.
- One unified EVdlc-style progress system (`TransferProgress` controller + shared renderer) for every transfer mode: single/parallel/file-in-folder downloads, folder downloads, single/parallel/directory uploads, and queue runs. Single transfers render as a one-row group of the same view; huge folders paint a bounded set of rows without losing totals; quiet mode (`-q`) skips the live view.
- Independent wall-clock `Elapsed` in every transfer mode: owned by the progress view's monotonic clock, refreshed by the renderer's own ticker even while producers are silent (stalls, retries, quota waits, finalization), frozen exactly at terminal state, and shown even on narrow terminals.
- Zero-byte upload support (single, directory, and queued): the completion token comes from an empty `POST <url>/0` per the MEGA protocol; zero-byte files also stream correctly (`Content-Length: 0`, no invalid upstream range request).
- Versioned upload resume identity (v2): path, size, `mtime_ns`, platform file id, and a FULL streaming SHA-256 of the content (bounded memory, cancellable, hashing cost logged for very large files). Resume and pre-finalization re-checks detect a change to any byte anywhere in the file — including zero-byte files, which are revalidated after the completion token and before node registration. Legacy states without an identity, and v1 sampled identities, are never treated as strict and restart fresh.
- Interrupted-queue recovery: `queue run` leases jobs with a run id + heartbeat, recovers jobs abandoned by a crashed/killed run as `interrupted`, re-runs them automatically, and never steals a live lease. New `queue retry <id|all>` returns failed/interrupted/canceled jobs to pending while preserving encrypted link passwords.
- Centralized upload success pipeline shared by sequential, parallel, flat/structured directory, queue, and auto-account uploads: success output, JSONL upload log, post-transfer command, optional `--share` link (directories share every uploaded file), and account attribution. Share/hook failures are reported separately and never turn a successful upload into a failure.
- Centralized config validation for `config set` and hand-edited files (ports, timeouts, worker counts, speed limits, quota waits, log settings, and typed optional keys including nested `elc_accounts`) with safe fallbacks and warnings that never echo secret values. Deprecated/unknown keys warn once per process, and the new `config migrate` command rewrites old config files without them.
- Machine-readable `--json` mode on `download` and `upload`: stdout carries only JSONL result records (success/failed/skipped, type, name, path, size, elapsed, handle, account, share link; sources key-redacted), human output and progress go to stderr — a stable interface for external callers such as EVdlc.
- Process/thread-safe queue: every queue mutation runs behind an instance mutex plus a cross-platform file lock with a bounded timeout, reloads the newest state before writing (a heartbeat can never revert a finished job, a stale writer can never clobber newer statuses), saves through unique fsync'd temp files, and `queue run` claims jobs atomically so two concurrent runs can never execute the same job.
- Isolated API clients for parallel downloads: each parallel transfer (and each folder worker, via `MegaAPIClient.clone()`) owns its own HTTP session and request sequence; every client is closed on completion. The shared proxy pool is explicitly thread-safe.
- `--auto-account` now re-plans after quota changes: accounts are selected immediately before each file from a live reservation ledger; a `QuotaError` refreshes that account's real quota and retries the same file on another suitable account (bounded to one attempt per account), and `--keep-structure` trees stay on one account or fail clearly.
- The overall progress state now reflects item outcomes: any failed or unfinished item makes the final Overall row `Failed` (matching the exit code) even when the command finished without an exception; queue progress rows always end in the job's real status, including canceled on Ctrl+C.

### Fixed
- Fixed a permanent hang in the bandwidth token bucket: `consume(amount)` with `amount` larger than the burst capacity (for example a 1 MiB upload chunk under a small rate limit) now drains incrementally and always makes forward progress.
- Speed limits are now true aggregate caps: all parallel workers of one command share a single limiter, instead of multiplying the configured limit per file.
- Parallel uploads are now thread-safe: each parallel file gets an isolated API client and HTTP session that reuses the authenticated session material (no MFA re-prompts, no shared request-sequence races), and worker cleanup no longer invalidates the shared session.
- Unified default-account resolution across upload, queue, share, and cloud commands: `--account` → vault default (`mb account default`) → legacy `config default_account`, with a one-time warning when the two stored defaults disagree.
- `--auto-account` now builds the file manifest first, selects by real per-file size (whole tree for `--keep-structure`), keeps an in-memory free-space ledger that decrements as files are assigned, refreshes cached quota after quota errors, and closes every temporary client.
- Failed transfers now produce non-zero exit codes in `download`, `upload`, and `queue run`; `--keep-going` continues processing but no longer reports overall success. Interactive selection answered with `none` is a documented skip, not a failure.
- Parallel downloads with identical or sanitization-colliding names can no longer race into the same destination/state file: final destinations are reserved atomically before workers start.
- Structured (`--keep-structure`) directory uploads now report real per-file and overall progress from a pre-computed manifest instead of a no-op callback, and run the same success pipeline per file.
- Upload result elapsed no longer resets on upload-URL refresh/retry and includes finalization; download elapsed includes integrity verification.
- `auto_resume=false` is honored by both downloads and uploads; `user_agent` is applied to API and transfer requests and defaults to the installed package version (no hard-coded version drift).
- Clipboard watching falls back to PowerShell/pbpaste/wl-paste/xclip when `pyperclip` imports but has no usable backend (not only when it is missing).
- Post-transfer hook commands are parsed with POSIX rules on Linux/macOS and Windows rules on Windows, never use `shell=True`, append the transferred path as exactly one argument, and no longer write hook arguments (which may carry secrets) to logs.
- Concurrent resume-state saves no longer crash with `PermissionError` on Windows (serialized save with brief replace retry).
- Fixed an intermittent deadlock between the folder-download live view and Rich's auto-refresh thread (lock-order inversion) that could freeze the progress UI and hang the CLI at completion.
- Fixed inflated download speeds at the start of resumed folder downloads: the live view no longer counts previously-downloaded bytes as instantaneous speed, and the overall speed is derived from the per-file meters (or a fresh backend hint) instead of a duplicate aggregate meter.
- Fixed the same lifetime-average speed bug on the upload side: upload progress now flows from a steady 0.5 s reporter thread with a rolling-window rate whose baseline excludes resumed chunks, instead of firing once per completed chunk future with `bytes_done / elapsed`.

### Deprecated
- Removed the never-functional config keys `chunk_size_kb`, `smart_proxy_autorefresh_minutes`, `smart_proxy_timeout_seconds`, and `smart_proxy_random`; `config set` now explains why and old config files load with a warning.

### CI
- The mypy-clean module set (CLI, commands, queue, accounts, UI, and new utility modules) is now a required type-check gate; the legacy full-tree run stays advisory. Local coverage regression below 55% now fails the test run (baseline ~61%).

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
