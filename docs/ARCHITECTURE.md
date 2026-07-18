# Architecture

MegaBasterd CLI is a source-run Python application. `Run.ps1` is the launcher,
and the importable package lives under `src/megabasterd_cli`.

## Runtime Flow

```text
Run.ps1
  |-- find Python 3.9+
  |-- create per-run logs under Logs/
  |-- check/import dependency modules
  |-- optionally create .venv and install requirements.txt
  |-- open the interactive menu when no CLI args are supplied
  |-- add src/ to PYTHONPATH
  `-- python -m megabasterd_cli <args>

src/megabasterd_cli/__main__.py
  `-- cli.main()

src/megabasterd_cli/cli.py
  |-- creates shared config/logging context
  `-- dispatches Click commands
```

## Package Layout

```text
src/megabasterd_cli/
|-- cli.py              # Click root command and subcommand registration
|-- config.py           # Config dataclass and project-local User/ paths
|-- commands/           # Thin command adapters
|-- core/               # MEGA protocol, crypto, transfers, links, state
|-- accounts/           # Encrypted account vault
|-- proxy/              # Smart proxy pool and CONNECT proxy
|-- queue/              # Persistent transfer queue
|-- streaming/          # Local HTTP stream server
|-- ui/                 # Rich theme, tables, prompts, progress
|-- native/             # Optional native helper sources/binaries
`-- utils/              # Logging, hooks, speed limiting, formatting
```

Tests live in `tests/`. Documentation lives in `docs/`. Helper build scripts
live in `tools/`. Packaging and tool configuration lives in `pyproject.toml`.

## Layers

```text
+-------------------------------------------------------+
| Launcher                                               |
|   Run.ps1 dependency check + Python dispatch           |
|   launcher transcript + CLI log file wiring            |
+-------------------------+-----------------------------+
                          |
+-------------------------v-----------------------------+
| CLI layer                                             |
|   Click root group + commands/*.py                    |
+-------------------------+-----------------------------+
                          |
+-------------------------v-----------------------------+
| Orchestration                                         |
|   MegaDownloader, MegaFolderDownloader, MegaUploader  |
|   StreamingServer, QueueManager                       |
+-------------------------+-----------------------------+
                          |
+-------------------------v-----------------------------+
| Protocol and crypto                                   |
|   MegaAPIClient, MegaClient, links.py, crypto.py      |
|   chunks.py, hashcash.py, state.py                    |
+-------------------------+-----------------------------+
                          |
+-------------------------v-----------------------------+
| Support systems                                       |
|   accounts vault, config, proxy pool, themed UI       |
+-------------------------------------------------------+
```

## Command Design

Command modules should stay thin:

- parse Click arguments;
- load config and account context;
- construct core objects;
- render results through `ui/`;
- leave protocol and crypto behavior in `core/`.

This keeps commands easy to test and avoids duplicating MEGA protocol logic.

## Theme Design

`ui/theme.py` defines a shared 20-color Rich palette. New UI code should create
consoles with `make_console()` and use the `mb.*` styles already registered in
the theme. This keeps tables, prompts, and progress bars visually consistent.

## Progress Architecture

All transfer modes (single/parallel/file-in-folder downloads, folder
downloads, single/parallel/directory uploads, queue runs) share one system:

- **Producers** (`core/downloader.py`, `core/uploader.py`) emit structured
  byte snapshots from a steady 0.5 s reporter thread; they know nothing about
  layout.
- **Controller** (`ui/transfer_progress.py`, `TransferProgress`) owns item
  registration, aggregation, the operation clock, and the lifecycle: every
  item ends in exactly one terminal state (`complete`/`failed`/`canceled`/
  `skipped`) and `close()` finalizes leftovers for every outcome (errors,
  cancellation, empty selections).
- **Renderer** (`ui/progress.py`, `MultiFileProgressView`) only paints
  controller state. Rich's auto-refresh re-invokes `__rich_console__` ~4×/s,
  so `Elapsed`, ETA, and speeds keep moving while producers are silent;
  speeds come from view-owned rolling meters that decay during stalls and
  treat the first (resume) sample as a baseline. `Elapsed` is wall-clock from
  one monotonic clock, frozen at terminal state, and never hidden (narrow
  terminals shrink the bar instead). Huge folders paint a bounded row set
  (active rows first) without losing overall totals.

Command modules must not duplicate layout logic; they only talk to
`TransferProgress`. Speed limits are aggregate per command: the command
builds one `TokenBucket` and every worker shares it.

The final overall state combines the context outcome with the item states:
any `failed` item — or any item still unfinished at `close()` time — makes
the overall state `Failed`, matching the process exit code; explicit user
skips stay successful.

## API-Client Ownership

`MegaAPIClient` owns one mutable `requests.Session`, a request-sequence
counter, and the SID slot; it belongs to exactly ONE concurrent transfer.
Commands build a fresh client per transfer (`MegaAPIClient.clone()` for
folder workers), and every client is closed on a `finally` path. Within one
`MegaDownloader`, chunk worker threads reach the API only through
`_refresh_url`, which is serialized by the downloader's `_url_refresh_lock`;
initial link resolution happens on the transfer's own thread before workers
start. The `SmartProxyPool` is the only intentionally shared object (every
method takes its internal lock). The aggregate `TokenBucket` limiter is also
shared by design and is thread-safe.

## Proxy Selection and Force Mode

`proxy/selector.py` is the single per-request proxy authority. `ProxySelector`
picks (1) a SmartProxyPool entry, (2) the static `--proxy` dict, or (3) refuses
with `ProxyRequiredError` when `force_smart_proxy` is on and nothing is
available - before any socket is opened, and with no direct fallback after a
proxy failure. Every outbound path selects here: API calls, chunk transfers,
the streaming CDN reads, MegaCrypter/DLC/ELC resolution, and `proxy fetch`.
`MegaAPIClient`, `MegaDownloader`, and `MegaUploader` delegate to it instead of
each keeping a private copy of the precedence rules.

## Streaming Range Validation

A nonzero Range decrypted at a nonzero AES-CTR counter is only correct if the
server honored the range. `streaming/server.validate_range_response` therefore
requires HTTP 206 with a `Content-Range` whose start, end, and total match the
request (and a `Content-Length` that matches the span) before a byte is
streamed. HTTP 200 is accepted only for a whole-file request, where the counter
starts at zero anyway. Anything else fails with 502 rather than serving
plaintext that belongs to a different offset.

## API Retry Policy

`core/api.py` classifies every request: actions in `READ_ONLY_ACTIONS` keep
bounded retries on any transport error, and everything else - including any
action not yet listed, so new commands fail safe - is MUTATING. A mutating
request is retried only when the failure is provably pre-commit (MEGA
rate-limiting, which means the server declined it, or a `ConnectTimeout`, which
means it was never sent). An ambiguous read timeout or mid-flight disconnect
raises `AmbiguousMutationError` instead of replaying a command the server may
already have applied.

## Resume State Integrity

`core/state.py` validates a `.mbstate` document before trusting it: object
root, known `transfer_type`, non-negative sizes, integer non-duplicate chunk
indexes (rejecting bools), fixed-length valid hex MACs with no orphan entries,
and an object `metadata`. Invalid hex is rejected at load time rather than
escaping later as a raw `ValueError` during verification. An untrustworthy file
is quarantined byte-for-byte and the transfer restarts fresh, which is the same
outcome `auto_resume = false` produces. Saves hold both the in-process mutex
and a cross-process advisory lock.

## Destination Reservation

`utils/helpers.claim_destination` reserves one destination for exactly one
transfer across PROCESSES, not just threads: it holds an advisory lock on a
`.mbclaim` sidecar for the transfer's lifetime and re-checks existence under
that lock (closing the TOCTOU window). Because the lock is advisory, the OS
drops it if the owner crashes, so a stale reservation can never permanently
block a valid future transfer.

## Corrupt-File Preservation

`utils/corruption.preserve_corrupt_file` is shared by the config store, the
queue, and resume state. Backups are deduplicated by CONTENT HASH, not by "a
backup already exists", so a second, different corruption episode is never
suppressed by an older one; the filename carries a timestamp plus the digest,
the file is created with `O_CREAT|O_EXCL`, and the caller is told `None` when
nothing could be written so no message claims a backup that does not exist.

## Shared File Lock

`utils/filelock.py` provides one bounded, cross-platform advisory lock
(`msvcrt.locking` on Windows, `fcntl.flock` on POSIX) used by BOTH
`QueueManager` and `ConfigStore`, so the locking code is written and tested
once. Each store wraps it with an instance re-entrant mutex and translates a
timeout into its own domain error (`QueueLockError` / `ConfigLockError`).

## Queue Concurrency and Integrity

`QueueManager` serializes every read-modify-write behind the instance mutex
plus the shared file lock. Mutations reload the newest queue from disk before
writing, so a stale snapshot can never clobber newer statuses and a heartbeat
can never revert a terminal state. `claim_next(run_id)` performs recovery +
selection + leasing atomically under one lock acquisition, which makes
concurrent `queue run` threads/instances/processes safe. Saves write a unique
fsync'd temp file and `os.replace` it over `queue.json`. On load, the file is
schema-validated (list root; each entry a dict with typed required fields and
known type/status); any violation is corruption — the original is preserved,
backed up once as `queue.json.corrupt.<ts>.json`, mutations are blocked
(`QueueCorruptionError`, non-zero CLI exit), and no queue key is created.

## Config Concurrency and Secrets

`ConfigStore` mirrors the queue contract: `set`/`unset`/`migrate` reload the
newest config under the shared lock, apply only the requested change, and
persist through a unique fsync'd temp file, so concurrent processes never lose
each other's updates. Load applies the same integrity contract as the queue:
invalid UTF-8/JSON or a non-object root is corruption — the original is
preserved, backed up once as `config.json.corrupt.<ts>.json`, and every
mutation raises `ConfigCorruptionError` (non-zero CLI exit) until
`mb config recover --reset`. `config show`/`get` redact secret values via
`config.display_value` (which reuses the machine-output sanitizer), and
`config set` never echoes a value. Nullable keys accept `null`/`none` to
store JSON null; `config unset` clears them.

## Machine Output and Redaction

`utils/redaction.py` is the single secret-redaction authority: `sanitize()`
recursively walks records (secret-named fields wholesale, embedded link keys
and secret query params in every string, `share_link` kept). `redact_text()`
also covers the free-text shapes that reach output through `str(exc)` —
`password: x`, `SID was x`, `MFA code 123456`, `api key = x`, `token is x`,
`Authorization: Bearer x`, and `scheme://user:pass@host` proxy credentials. `MachineOutput`
sanitizes each `--json` record and writes it as one atomic
`dumps(...) + "\n"` under a lock, so parallel workers never interleave partial
lines. `transfer_progress.redact_link` and `config.display_value` delegate to
the same module.

## Parallel `--auto-account`

Flat-file auto-account uploads run concurrently under `-P N`: each file
reserves bytes from the thread-safe `QuotaLedger` immediately before it
starts, gets its own isolated worker client (via `MegaAPIClient.clone`/session
reuse — one login per account, no repeated MFA), and closes it when done. The
account store's `update_quota` and vault save are lock-protected so
concurrent quota refreshes cannot corrupt the vault. `--keep-structure` trees
remain one-account and sequential.

## Upload Resume Identity

Upload state records a versioned (v2) source identity: canonical path, size,
`mtime_ns`, platform file id, and a FULL streaming SHA-256 of the content.
Resume and pre-finalization checks recompute the hash, so a change to any
byte anywhere in the file is detected (zero-byte uploads included). Legacy
v1 sampled identities are never trusted; such uploads restart fresh.

## Transfer Invariants

### Crypto is deterministic

`core/crypto.py` and `core/chunks.py` are pure helpers. They should not perform
network calls, filesystem writes, or config reads.

### Transfers are restartable

Downloads and uploads write `.mbstate` files next to transfer targets. State
contains completed chunks and MAC metadata so an interrupted command can resume
without redoing finished chunks.

### Parallelism is per transfer

One file transfer owns a thread pool of chunk workers. Folder and multi-file
operations can run several file transfers concurrently, each with its own chunk
workers.

### Integrity is explicit

Downloaded chunks are folded into MEGA's final CBC-MAC. Mismatches raise an
integrity error and leave the state file in place.

### Account secrets are encrypted on disk

The account vault encrypts stored passwords with AES-GCM and a scrypt-derived
key. The vault passphrase is requested interactively unless a command receives
`--vault-passphrase`.

## MEGA Protocol Notes

### File keys

MEGA file keys are eight uint32 values. The first four are XORed with the last
four to recover the AES key and metadata:

```text
[ aes_xor_nonce_hi, aes_xor_nonce_lo, aes_xor_mac_hi, aes_xor_mac_lo,
  nonce_hi,         nonce_lo,         mac_iv_hi,      mac_iv_lo        ]
```

`core.crypto.unpack_file_key` returns `(aes_key, nonce, mac)`.

### Chunk sizing

The first eight chunks grow from 128 KB to 1024 KB. Later chunks stay at 1024
KB. `core.chunks.iter_chunks` centralizes this pattern.

### Folder node keys

Files inside public folder shares store per-node keys wrapped by the folder key.
Folder-file and folder-subtree operations must fetch the parent folder listing,
unwrap the target node key, and then request the CDN URL in folder context.

### Hashcash challenges

MEGA may return an `X-Hashcash` challenge for API throttling. `core/hashcash.py`
solves the challenge and verifies the returned nonce before retrying. On
Windows, the solver prefers `Bin/hashcash-solver-win64.exe` when it exists, then
the bundled PowerShell/.NET helper in `tools/hashcash_solver_windows.ps1`, and
finally the pure-Python fallback. Set `MEGABASTERD_HASHCASH_NATIVE=0` to disable
native helper use.

## Extension Points

- Add link formats in `core/links.py`.
- Add public-link metadata renderers in `commands/info_cmd.py`.
- Add transfer behavior in `core/downloader.py` or `core/uploader.py`.
- Add new cloud operations to `core/client.py` and expose them from
  `commands/cloud_cmd.py`.
- Add UI styles in `ui/theme.py`, then consume them through `make_console()`.
