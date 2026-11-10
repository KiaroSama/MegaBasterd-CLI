# Native Architecture

The application is a standalone Rust CLI. Three small Rust entrypoints call one
dispatcher. There is no interpreter bridge; historical source remains in Git.

Build and test evidence is recorded by the native CI matrix for each commit.

## Responsibilities and dependency direction

```text
src/main.rs
  -> cli/          clap schema, command adapters, interactive menu
  -> transfers/    download/upload orchestration, claims, resume, controls
  -> services/     local files/media, stream/CONNECT servers, child commands
  -> protocol/     MEGA API/auth/nodes/links/HTTP/routing contracts
  -> crypto/       wire primitives, file keys, CTR, MAC, KDFs

storage/           versioned private configuration/vault/queue/state
platform/          native anchored files, permissions, identity, child ownership
terminal/          safe output, prompts, progress, input and per-run logs
```

CLI adapters own configuration/account selection and presentation. Crypto does
not read settings, launch tools or contact a service. Protocol data stays explicit;
filesystem/network/terminal effects sit at their owning boundaries. Small concrete
modules are preferred over an interface/factory with no second implementation.

| Area | Main responsibilities |
| --- | --- |
| `cli/args.rs`, `cli/mod.rs` | Exact schema, dispatch, output mode, exit codes and cancellation. |
| `crypto/` | Base64/u32 wire data, AES block wrapping, attributes, CTR, ordered MACs and login/link KDFs. |
| `protocol/api.rs`, `auth.rs`, `nodes.rs`, `shares.rs` | Action-aware requests, session verification, cloud graph and mutations. |
| `protocol/transport.rs`, `dns.rs`, proxy modules | Validated HTTPS, address pinning, proxy selection, redirects and bounded bodies. |
| `storage/` | Fresh versioned stores, encrypted payloads, locks, reload/atomic writes and leases. |
| `transfers/` | Bounded workers/limiters, actual transfer bytes, source identities, stage publication and receipts. |
| `services/` | Local authenticated encryption/split/merge/media, HTTP services and literal child arguments. |
| `platform/` | Windows/Unix-specific handle/file/process contracts. |
| `terminal/` | Central redaction, serialized machine output, shared logging, prompts and progress. |

## CLI and output contracts

The baseline inventory contains 55 leaf commands: 16 root leaves and 39 inside
six groups, with 131 explicit source option declarations. Added download account
flags are tracked separately. Aliases `mb`, `mbcli`, `megabasterd-cli` share the
same parser. Public behavior is the command interface; Python import APIs are
retired, not bridged.

`Output` serializes complete JSON/JSONL records under one lock. Human diagnostics
use stderr; table/public-link output uses the appropriate explicit interface.
Redaction covers nested secret fields, link keys, credential URLs and free-text
secret forms. Deliberately public share links are an explicit exception, never a
reason to copy other keys into logs.

`Context` and `Output` share one logger. Console thresholds/quiet do not suppress
file events; structured context events avoid double logging. Logs are private,
unique per run, UTF-8/UTC, with current-run-only rotation. Before `Started`, the
logger fixes `run` to its selected basename stem and `cmd` to an exhaustive static
root-command label (`unknown` for public library constructors). Every record keeps
its level/component and the same run/command context, including rotated segments;
raw arguments are never used as labels. Logging failure has a safe warning and
never an insecure file reopen. The executable installs a panic hook that captures
bounded command-thread payload/location and a native backtrace into a scoped
thread-local slot. Sanitization and private logging happen after unwind, never
under the hook or a logger lock. Nested scopes restore prior state and successful
commands discard internally caught panic details. Backtrace capture itself is
platform-managed and not a bounded-time recovery guarantee; aborting and worker
panics remain outside this command-thread recovery contract.

Progress owns structured rows and a joined TTY renderer. A snapshot exposes
immutable total/completed/status for observation without creating a test-only
transfer engine. Terminal states freeze elapsed and remove ETA. Interactive `p`
changes shared pause state; Ctrl+C cancels and wakes waiters. Piped/JSON commands
do not start the raw keyboard listener. Actual PTY restoration/visual parity is
a native verification requirement, not established by this document.

## API, routing and mutation ownership

Each concurrent transfer has its own mutable API/session sequence state. Shared
pool/limiters/control are synchronized deliberately; mutable account clients are
not shared unsafely between transfer workers. URL refresh within a download is
serialized with a generation check.

API actions are classified conservatively. Reads may retry bounded transport
failures; unknown/mutating actions never replay an uncertain sent request.
Typed definitive MEGA rejection is distinct from cancellation, TLS failure,
malformed response and unknown mutation outcome. Ambiguity diagnostics identify
only allowlisted action names or fixed `unknown`/`batch` labels, never arbitrary
action text or request data. Account, queue and upload-journal stop fences retain
the same ambiguity classification and non-retryable exit behavior.

API response collection is incremental and capped at 64 MiB after identity/gzip
decoding; an oversized declared length is rejected before reading. HTML and
non-array result diagnostics describe the failure without echoing arbitrary
headers or bodies. Origin HTTP errors do not blame or credit a selected proxy;
HTTP 407 and unusable bodies do. Credit requires a usable result, and each
response owns its connection until it is consumed or rejected. Actual native
socket closure and attribution fixtures are exercised by native tests.

Hashcash accepts both the retained `1:easiness:token` challenge and the current
SDK's `1:easiness:timestamp:token` form. Their solution headers are respectively
`1:easiness:token:nonce` and `1:token:nonce`; the timestamp is informational.
Parsing bounds the header and encoded token before decoding and requires a
48-byte token, version 1 and an unsigned-byte easiness. Proofs hash a four-byte
big-endian nonce followed by 262,144 copies of that token, incrementally rather
than allocating the complete repeated input.

One absolute 30-second deadline covers an API request's challenge handling, with
at most two solves. Pause waits, each 12 KiB hash batch and the completed hash
check cancellation and expiry; a late solution cannot authorize another request.
Ordinary transfer pause checkpoints retain their deadline-free behavior. A 402
rejection may be answered with a proof, but an uncertain sent mutation after that
proof is still not replayed. Independent SHA-256 vectors and direct/CONNECT peer
fixtures cover these contracts in source; native CI executes these tests.

Trash/import batches return successful handles plus definitive rejections in
`BatchOutcome`. They continue definitive sibling failures and invalidate cached
listings; the CLI's completeness gate makes partial batches nonzero instead of
printing all-success messages. Ambiguity/cancellation stops immediately. Imports
forward retained, validated original attribute ciphertext and rewrap full node
keys; reserializing JSON is not byte-preserving. Failed-parent descendants retain
the baseline fallback to the explicitly selected destination.
Account listings preserve structurally valid unavailable-key nodes as metadata,
without a usable key or guessed filename; unrelated owned nodes remain accessible.
Public-share/content decoding stays strict. Export refuses missing key material
before publishing a link. Search uses only decoded names and is case-insensitive
for both substring and regex modes.

Own-cloud commands require authenticated context before requesting a listing or
mutation. Missing nodes and unavailable keys return typed, nonzero errors without
echoing the target or key. Folder creation invalidates the listing even when a
sent request returns malformed registration data: its outcome is ambiguous and
must not be replayed; a later explicit listing can reveal the committed folder.
Trash cleanup deletes only direct children of the trash root; an empty listing
sends no deletion. Persistent parsed-command and TLS peer fixtures express these
contracts, but native CI executes these tests.

Every remote path uses the selected transport policy: HTTPS without embedded
service credentials, verified host/certificate, bounded response, public resolved
destinations and validated redirects. Trusted explicitly configured proxy endpoints
are separate from target DNS. Forced proxy mode never silently connects directly.
The narrow pinned HTTP/HTTPS CONNECT/SOCKS5H adapter preserves original target
Host/SNI while dialing validated numeric addresses, including bounded failover.
No target gets a MEGA-hostname exception to public-address/TLS rules.

## Folder selection and wildcard compatibility

`transfers/planner.rs` owns safe relative destinations and re-exports `Filter`;
`transfers/folder_filter.rs` owns bounded source-style wildcard compilation using
the existing regex engine. User patterns are not regular expressions: literals
and character-class endpoints are escaped, braces stay literal, and repeated stars
collapse. The pinned `unicode_fold.rs` table preserves the source interpreter's
Unicode 14 full folding independently of the compiler's Unicode release. Its
Unicode notice is included with project licenses. An independent source-only
oracle supplies 360 pattern match sets over 32 subjects; native execution of those
assertions remains a verification gate, not a claim made by this document.

## Crypto contracts

MEGA wrapping encrypts independent AES blocks, not chained CBC. Attribute
ciphertext uses AES-CBC/zero IV. Files have an eight-u32/32-byte raw key:
XOR of its first/last four words yields AES material; words 4–5 are the nonce,
words 6–7 the condensed MAC. CTR offset includes the intra-block byte position.

Chunks grow from 128 KiB to 1 MiB in 128 KiB steps, then remain 1 MiB. Ordered
chunk CBC-MACs fold into the final file MAC; final download verification rereads
the actual disk file. Independent source-generated vectors, not the Rust result
itself, supply expected keys/ciphertext/hash values.

Vault/session/upload-key envelopes use AES-256-GCM with context-bound associated
data and explicit scrypt parameters. Each vault retains at most 32 zeroizing derived
keys in a private FIFO cache, indexed by the salt and complete validated cost tuple.
Derivation is serialized per vault; every open still authenticates its ciphertext
and associated data. Eviction and vault destruction drop the wrapped keys; no
measured speedup or physical memory-erasure guarantee is claimed.
Local MBCR v2 authenticates sequence/final
records; v1 reads warn about their weaker contract. Zeroizing buffers are used
for sensitive material where supported. Big-integer RSA is not claimed constant-
time or fully zeroized merely because other buffers are.

## Storage and native file boundaries

The native namespace is `User/native-v2/`, or `native-v2` under the configured
user base. Python stores are untouched. Documents use version 2 envelopes.
A persistent sidecar lock spans reload → validation → private same-directory
stage → flush/fsync → atomic replace. Corrupt/future/foreign state fails closed.
Explicit recovery preserves original bytes before resetting; no silent rewrite.
Transfer owners claim checked, increasing snapshot revisions while holding their
existing transfer lock. The state store reloads under its sidecar and ignores a
snapshot older than the committed revision without changing saved bytes. Equal
revisions may be saved again; a newer revision may intentionally remove coverage
that resume validation rejected. Revision overflow refuses without wrapping. Persisted upload URLs still require
HTTPS, no embedded credentials, public-address policy and the exact MEGA host
boundary; malformed encrypted-key envelopes are refused before use. Invalid
stored values report saved-data corruption without echoing the rejected URL.

Private files are owner-only before the first byte. Native directory handles
anchor subsequent operations; Windows DACL/file IDs and Unix nofollow/openat/
owner/link/mode checks do not fall back to unchecked paths. File identity is
compared while the relevant handles are live. UNC is deliberately unsupported;
unsupported directory-sync behavior is explicit, not fabricated durability.
On Windows, read/list ancestor handles deny delete sharing while publication renames
the exact source handle to an absolute UTF-16 destination. Overwrite uses
`FileRenameInfoEx` with POSIX semantics so the verified, delete-shared destination
handle remains live until replacement finishes. No-overwrite publication keeps
its refusal when the destination already exists.

Downloads hold persistent `.mbclaim` sidecar locks and stage output separately.
Resume checks stored source/key/destination identity and recomputes actual local
chunk MACs before reuse. Only verified/explicitly permitted output is published.
The shared verification permit bounds simultaneous disk rereads and is released
on all outcomes.

Uploads keep full SHA-256/size/mtime/native held-object/current-path identity.
Changed in-flight content cannot register a mixed remote file. Only matching
known-unregistered upload state may be discarded after proved mutation;
registration markers/confirmed receipts remain protected. The receipt survives
local finalization failure and prevents blind duplicate registration.
Structured uploads additionally retain a locked folder journal: lookup/key preparation
precedes the pre-send mutation intent; confirmed parents and per-file receipts survive
sibling failures. Completed file finalization is not replayed. Unknown finalization
requires reconciliation, not another thumbnail/share/hook attempt. A durable completion
tombstone replaces unlink-based acknowledgement; retained receipts are not garbage-collected
by broad scans. These recovery paths still require native CI execution.

Queue payloads are encrypted, including source/destination/account/error fields
when no password is supplied. Atomic claims, retained execution locks and lease
generations fence stale writers; expiry alone cannot steal a running executor.
Heartbeats continue while paused. Each heartbeat lock attempt is capped by the
remaining renewal grace, the interval and the normal 10-second store timeout;
a renewal returning after grace stops the transfer rather than restoring health.
The synchronous executor must honor cancellation and reap its workers before
returning. A queue job row exists before preparation and is marked Done only
after the queue commit; missing local inputs, failures and cancellation retain
terminal rows. File executors own live rendering, and final queue rows are
reported afterward through the existing bounded progress formatter, without
starting a second renderer or writing to machine stdout. Unknown remote mutation
does not become automatic retry. Native race, deadline, progress and recovery
tests run in the native matrix; source assertions alone are insufficient.

## Local services and child processes

Streaming validates HTTP framing and exact upstream ranges before CTR decrypt.
Non-loopback access is authenticated, query tokens opt-in. HTTP workers/listeners
and paused waiters share cancellation/shutdown ownership. CONNECT forwarding is
MEGA-domain restricted and authenticated, not a generic open proxy.

Media input remains an opened regular-file handle. Images have encoded/pixel/
allocation limits and no-upscale aspect bounds. Video/audio uses seekable
`fd` input from inherited regular-file stdin, a protocol whitelist and bounded
ffprobe/ffmpeg output/time.
Hardware decode is requested before a reported CPU fallback. Generated JPEG is
encrypted under the file AES key, uploaded via `ufa`, and attached with an exact
eight-byte attribute handle via `pfa`.

Child commands receive literal argument vectors, hidden Windows startup, bounded
captures and owned process-group/job cleanup. No shell evaluation, automatic media
installation, background daemon or hook installation is part of this design.
Native process-tree/pipe/cancellation tests remain required.

## Verification and distribution

`tests/fixtures/cli-schema.json` records the independently transcribed source
schema. Crypto, link, local-file and transfer vectors retain source provenance.
The parity ledger keeps all 1,416 baseline definitions across 164 modules.
`cargo xtask verify` checks target hashes, discovers and executes the native
harnesses, then reconciles each applicable mapping with actual passing results.
Receipts include the exact commit, native OS and architecture; static source
inspection alone never marks a test passed.

Rust CI runs on every push and pull request. Native runners build Release
binaries for Windows, Linux, macOS Intel and macOS Apple Silicon. Separate
formatting, Clippy/type, dependency-policy and LLVM coverage checks preserve the
previous check categories and 76% line-coverage floor. The CI driver and packaging
tool are Rust (`xtask/`). Test-only FFmpeg/ffprobe prerequisites use pinned archives
and checksums; no runtime install step is part of the application.

[Migration notes](MIGRATION.md) document the native storage/compatibility boundary;
[upstream review](UPSTREAM.md) records the relevant Java behaviors ported to Rust.
