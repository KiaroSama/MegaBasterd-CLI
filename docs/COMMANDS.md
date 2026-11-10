# Native Command Reference

The native commands are `mb`, `mbcli` and `megabasterd-cli`. They share one Rust
dispatcher. The [README](../README.md#all-commands) lists all 55 leaf commands;
append `--help` to a command for executable usage.

## Root options and shared authentication

| Option | Meaning |
| --- | --- |
| `-h`, `--help` | Show help for the selected command/group. |
| `--version` | Show version at the root; no `-V` alias. |
| `-v`, `--verbose` | INFO console diagnostics; `-vv` selects DEBUG. |
| `-q`, `--quiet` | Suppress non-error console messages. |
| `--log-file`, `--no-log-file` | Override file logging for this invocation. |

Place root flags before the command in portable scripts. Repeated scalar flags
use the last value; repeated include/exclude flags accumulate and verbosity
counts. Opposite logging switches use the last selected switch.

Account options (`AUTH` below): `-a/--account EMAIL_OR_LABEL`,
`--vault-passphrase TEXT`, `--mfa-code CODE`. Vault-only options (`VAULT`) are
`--vault-passphrase TEXT` and `--mfa-code CODE`. Avoid secrets in command-line
arguments: they can reach shell history/process listings. Prefer interactive
secret prompts or the supported private `MEGABASTERD_VAULT_PASSPHRASE` environment
input for vault unlock. Never send MFA codes in a bug report.

Account selection: explicit account → account-vault default → configured
`default_account`. An explicit account authentication failure must not silently
become an anonymous transfer. Public `info` does not authenticate.

## Downloads

```bash
mb download [URL ...] [OPTIONS]
```

| Option | Meaning |
| --- | --- |
| `-o`, `--output DIR` | Destination directory; config/root `Output/` by default. |
| `-w`, `--workers N` | Chunk workers, 1–64; default `max_workers` (8). |
| `-P`, `--parallel N` | Parallel files, 1–32; default `max_parallel_downloads` (6). |
| `-l`, `--limit KBPS` | Aggregate KiB/s cap; finite nonnegative, 0 unlimited. |
| `-p`, `--password TEXT` | Protected-link password. |
| `--no-verify` | Disable final disk MAC verification; reduces integrity assurance. |
| `--overwrite`, `--force` | Permit replacement instead of unique-name preservation. |
| `--rename NAME` | Override a single file's local basename. |
| `--proxy URL` | Explicit validated proxy for this invocation. |
| `-i`, `--input-file PATH` | Existing UTF-8 link list or DLC input file. |
| `--elc-user TEXT`, `--elc-api-key TEXT` | Selected ELC service credentials. |
| `-I`, `--include GLOB` | Repeatable folder include filter. |
| `-X`, `--exclude GLOB` | Repeatable exclusion; exclusions win. |
| `--select` | Interactive folder selection; `1,3-5`, `all`, `none`. |
| `--json` | JSONL result records on stdout, diagnostics on stderr. |
| `AUTH` | Optional stored-account-backed public downloads. |

A URL list, a supported container or an input file supplies the source. Supported
formats include public/legacy MEGA file and folder links, file/subfolder links,
password links, `mega://enc`, `mega://fenc`, ELC, DLC and MegaCrypter.
Folder include paths preserve double spaces and match `info --json` file paths.
EOF at selection cancels cleanly. An explicit empty selection is a skip, not a
successful download of nonexistent content.

Final output is staged until verification/publication. Resume rereads staged
bytes before trusting completed coverage. An unrelated destination is preserved
under the default unique-name policy. Persistent `.mbclaim` lock sidecars are
intentional. Do not delete state or partial files blindly after an error.

## Uploads

```bash
mb upload PATH ... [OPTIONS]
```

Paths must exist and may be files or directories. Authentication uses `AUTH`.

| Option | Meaning |
| --- | --- |
| `-w`, `--workers N` | Chunk workers, 1–64; default `upload_workers` (4). |
| `-P`, `--parallel N` | Parallel files, 1–32; default `max_parallel_uploads` (1). |
| `-l`, `--limit KBPS` | Aggregate finite nonnegative KiB/s cap. |
| `--rename NAME` | Remote basename for a single file. |
| `--target HANDLE_OR_PATH` | Destination cloud folder. |
| `--keep-structure` | Recreate a local directory hierarchy. |
| `--keep-going` | Retain the directory partial-result path after ordinary item errors; final failure remains nonzero. Strict structured uploads also attempt independent siblings before returning an aggregate transfer failure. |
| `--auto-account` | Select a suitable cached-quota account per file. |
| `--share` | Create a public link after successful upload. |
| `--share-password TEXT` | Password-wrap a requested share link. |
| `--json` | JSONL result records. |

Automatic selection requires cached quotas from `account refresh-all`; a
structured tree stays on one account. Whole-source hash/file identity checks
protect resume/final registration. A confirmed registration receipt is retained
until local finalization is acknowledged; uncertain registration is never
blindly replayed.

Media uploads automatically attempt an encrypted thumbnail. Image decoding is
built in; video/audio needs `ffmpeg`/`ffprobe`. A missing codec/tool, rejected
attribute, public-share error or post-transfer hook error is reported separately
and does not turn already uploaded file bytes into a failed upload. JSON upload
results include `thumbnail.status` (`attached`, `not_applicable`, or `failed`),
with a separate warning/error code where applicable. Native integration proof
for these paths runs in CI.

## Streaming and public metadata

```bash
mb stream URL [OPTIONS]
```

Options: `-p/--port PORT`, `-H/--host HOST`, `--password TEXT`, `--token TEXT`,
`--allow-query-token`, `--proxy URL`, `--elc-user TEXT`, `--elc-api-key TEXT`.
Defaults are `streaming_port=8080` and `streaming_host=127.0.0.1`.
The source must resolve to exactly one file. Range responses are checked before
CTR decryption at the selected byte offset. HEAD does not fetch the upstream
body. A non-loopback listener requires authentication; if no token was supplied,
the generated token is saved privately under the native data directory and only
its location is reported. Use `Authorization: Bearer <token>`. Query tokens are
opt-in because URLs may leak. Ctrl+C stops owned clients/workers.

```bash
mb info URL [--json] [--password TEXT] [--elc-user TEXT] [--elc-api-key TEXT]
```

No account/MFA or content download is required. JSON is one object, not JSONL
human chatter. Folder data includes integer `file_count`, `node_count`,
`total_size` and `files[{path,size,handle}]`; names and double spaces are preserved.
Normal private logs/config access can still create runtime data: this command
is not a promise of zero filesystem activity.

```bash
mb share TARGET [--password TEXT] [--remove] [AUTH]
```

Create/password-wrap or remove an account-owned node's public link. An
intentionally exported `share_link` includes its public key; other diagnostic
link keys remain redacted.

## Cloud and trash

All commands below accept `AUTH`.

| Syntax | Meaning |
| --- | --- |
| `mb ls [PATH] [--all]` | List children, a selected file or the account node listing. |
| `mb mkdir NAME [--parent TARGET]` | Create a folder. |
| `mb rm TARGET [--yes]` | Request remote deletion; confirmation otherwise. |
| `mb mv SOURCE DESTINATION` | Move into a folder; refuse cycles/system roots. |
| `mb rename TARGET NEW_NAME` | Rename while preserving other attributes. |
| `mb search PATTERN [--regex]` | Search names, optionally using a regular expression. |
| `mb import SHARE_URL [--target TARGET]` | Server-side folder/subtree import. |
| `mb trash list` | List trash children. |
| `mb trash empty [--yes]` | Permanently delete trash children. |

Definitive individual rejection does not erase successful sibling changes.
Partial batches return failure rather than printing an all-success message.
Cancellation/ambiguous mutation stops immediately; inspect remote state before
retrying. Imports forward original validated attribute ciphertext and rewrap
full node keys. If a parent import is rejected, surviving descendants use the
explicit selected destination, preserving the source application's fallback.

## Accounts

| Syntax | Options / behavior |
| --- | --- |
| `mb account list` | Stored identities, not passwords. |
| `mb account add EMAIL` | `--password`, `--label`, `--default`, `--vault-passphrase`, `--verify`/`--no-verify`, `--mfa-code`. Verification is on by default; opposite switches use the last selection. |
| `mb account remove EMAIL_OR_LABEL` | Remove credentials/session with confirmation. |
| `mb account logout [EMAIL_OR_LABEL]` | `--all`, `--vault-passphrase`; end sessions without removing credentials. |
| `mb account default EMAIL_OR_LABEL` | Set the vault default. |
| `mb account info [EMAIL_OR_LABEL]` | `VAULT`; fetch account/quota information. |
| `mb account refresh-all` | `VAULT`; update cached quotas. |

Passwords and sessions are encrypted. A definitive expired session may be
removed; transport/suspicious-validation failures preserve stored bytes.
Logout and remove are different operations, not aliases.

## Queue

| Syntax | Options / behavior |
| --- | --- |
| `mb queue list` | Inspect job status. |
| `mb queue add-download URL` | `-o/--output DIR`, `-p/--password TEXT`. |
| `mb queue add-upload PATH` | Existing file; `-a/--account ID`. |
| `mb queue remove ITEM_ID` | Remove one eligible job. |
| `mb queue retry ITEM_ID` | Accepts `all`; requeue eligible failed/interrupted/canceled work. |
| `mb queue clear` | Confirm clearing completed/canceled jobs. |
| `mb queue reset` | Explicitly confirm discarding current queue; corrupt data is preserved first. |
| `mb queue run` | `VAULT`; execute jobs under leases/heartbeats. |

Queue payloads are encrypted. Atomic claim/generation checks prevent stale
owners from finishing another owner's job. Unknown remote mutation remains
active for reconciliation rather than automatically retrying it. Corrupt/future
stores are not silently replaced. Native process tests cover this behavior.

## Proxies

| Syntax | Options / behavior |
| --- | --- |
| `mb proxy list` | `--config-urls`/`--no-config-urls`; configured URLs included by default. |
| `mb proxy add URL ...` | Validate and store URLs. |
| `mb proxy remove URL` | Remove one URL. |
| `mb proxy clear` | Clear the stored pool. |
| `mb proxy import PATH` | Existing local text file. |
| `mb proxy fetch` | `--protocol http\|socks4\|socks5` (http), `--source URL`, `--limit N` (200), `--timeout SECONDS` (20). |
| `mb proxy test` | Bounded TCP reachability; not a complete proxy handshake/trust test. |
| `mb proxy serve` | `-p/--port PORT`, `--password TEXT`, `--any-port`; loopback listener, configured defaults. |

Supported routing URLs include HTTP, HTTPS, SOCKS4, SOCKS5 and SOCKS5H. Embedded
proxy credentials are redacted in displays. Local pool reload preserves
compatible health/cooldown state; bad reloads do not silently replace a healthy
pool. Forced mode refuses when no allowed proxy is available, without a direct
fallback. CONNECT/HTTP forwarding remains restricted to MEGA domains; `--any-port`
changes port policy, not domain policy.

## Crypter, containers and local files

| Syntax | Options / behavior |
| --- | --- |
| `mb crypter encrypt SOURCE DESTINATION` | Existing file; `--password TEXT`, `--chunk-size-kb N` (64). The unit is KiB, not MiB. |
| `mb crypter decrypt SOURCE DESTINATION` | Existing file; `--password TEXT`. |
| `mb crypter make-link MEGA_URL` | `--server`, `--password`, `--description`, `--no-expire`, `--reverse`, `--max-downloads`. |
| `mb crypter resolve MC_URL` | `--password TEXT`. |
| `mb crypter elc-resolve ELC_URL` | `--user TEXT`, `--api-key TEXT`. |
| `mb crypter dlc-resolve PATH` | Existing DLC file, trusted HTTPS resolver. |
| `mb split SOURCE PART_SIZE_MB` | `-o/--output-dir DIR`; numbered parts plus SHA-1 sidecar. |
| `mb merge ANY_PART` | `-o/--output FILE`, `--no-verify`, `--delete-parts`. |
| `mb thumbnail SOURCE DESTINATION` | JPEG within 250x250, aspect preserved, no upscaling. |

File encryption writes authenticated MBCR v2; reading legacy v1 explicitly warns
about its weaker sequence/trailing-data guarantees. Cipher chunk sizes are
bounded; wrong passwords/corrupt input must not replace a prior output. Merge
checks SHA-1 unless explicitly disabled; part deletion is opt-in and only follows
successful publication. Thumbnail outputs preserve input aliases/existing files;
video/audio requires a supported external tool pair.

## Clipboard and settings

```bash
mb watch [--interval SECONDS] [-o DIR] [--run] [VAULT]
```

Default interval 1.5 seconds, valid inclusive range 0.05–3600. Queue newly copied
MEGA links; `--run` also runs pending jobs. No application-owned clipboard daemon
is installed; Ctrl+C ends the command. A usable platform clipboard is required.

| Syntax | Meaning |
| --- | --- |
| `mb config show` | Display sanitized settings. |
| `mb config get KEY` | Display one sanitized setting. |
| `mb config set KEY VALUE` | Validate and persist one setting. |
| `mb config unset KEY` | Clear a nullable setting. |
| `mb config reset` | Confirm restoring defaults, not corrupt-file recovery. |
| `mb config path` | Active path. |
| `mb config migrate` | Normalize supported native settings and remove retired/unknown keys; never imports Python-era stores. |
| `mb config recover [--reset]` | Diagnose corruption; explicit reset preserves original bytes. |

See [CONFIG.md](CONFIG.md) for defaults, storage envelopes, secret fields and
log retention. Exit codes: 0 success/skip, 1 operation failure, 2 usage error,
130 cancellation. CI records executed command contracts.
