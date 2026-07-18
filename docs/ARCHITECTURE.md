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

## Queue Concurrency

`QueueManager` serializes every read-modify-write behind an instance mutex
plus a cross-platform file lock (`msvcrt`/`fcntl`, bounded timeout →
`QueueLockError`). Mutations reload the newest queue from disk before
writing, so a stale snapshot can never clobber newer statuses and a
heartbeat can never revert a terminal state. `claim_next(run_id)` performs
recovery + selection + leasing atomically under one lock acquisition, which
makes concurrent `queue run` threads/instances/processes safe. Saves write a
unique fsync'd temp file and `os.replace` it over `queue.json`.

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
