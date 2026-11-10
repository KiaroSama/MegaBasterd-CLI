# Native Usage Guide

Install a native binary or build from source using the [README](../README.md#installation).
All examples use `mb`; `mbcli` and `megabasterd-cli` are equivalent aliases.

## Interactive menu

Run `mb` without arguments in a terminal to open the native menu. Its original
numbered actions remain: `1` download, `2` link info, `3` upload and `8` advanced
CLI arguments. Settings retains the default download-folder, worker and speed-limit
shortcuts. Download and upload guides collect the original worker, parallel-file, speed-limit and secret
options; link inspection, account setup and ELC credentials have guided prompts.
Enter keeps the displayed default. `0` or `back` returns one step; at a speed-limit
prompt, use `back` because `0` means unlimited. `exit` or end of input leaves the
wizard. Empty required values and invalid numbers are requested again. Optional
secrets are hidden and may be left blank; required authentication still asks for
them when needed. Account logout remains available in both account and settings
menus and never means deleting the stored credential.

Menu numbers use cyan keys, with a green `[1]` marker on the Enter default;
labels keep the terminal's default foreground. Prompts leave brackets and braces
plain, with green default values, orange back hints and blue exit hints. Textual
labels remain available without color. A nonempty `NO_COLOR` disables automatic
color, and redirected output stays plain. Menu chrome goes to stderr, never JSON
stdout.

Noninteractive use requires a command such as `mb --help`; it does not read a raw
menu or transfer keyboard listener. Hidden answers are bounded to 64 KiB of UTF-8.
Unix visible prompts retain the terminal's cooked editing and refuse answers at
its reported safe line capacity instead of accepting possible kernel truncation;
pass long values as CLI arguments. Menu and terminal behavior are still awaiting
native/PTY tests on the supported platforms.

## Start with public metadata

After installing a verified native binary, inspect its help:

```bash
mb --help
```

Inspect a public folder without an account or file-content download:

```bash
mb info 'https://mega.nz/folder/ID#KEY' --json
```

`ID`/`KEY` in examples are placeholders. Folder JSON contains `file_count`,
`node_count`, `total_size` and `files` entries with integer-byte `size`, exact
`path` and `handle`. Copy a path literally into a download include filter;
double spaces in names matter. Runtime logs/config may be created normally.

## Download and resume

```bash
mb download 'https://mega.nz/folder/ID#KEY' -I '*.mkv' -X '*sample*' -o downloads
```

```bash
mb download -i links.txt -w 8 -P 3 -l 4096
```

The cap is aggregate KiB/s for the command, not per worker. Default output is
`Output/` beside the native executable, unless configured/overridden. Folder
hierarchies and exact sanitized include paths are shared with `info`.
Include/exclude wildcards preserve the source client's Unicode 14 full case folding,
so `STRASSE.*` matches `Straße.mkv`. `*`/`?` may match separators; braces are literal,
not alternatives. Exclude wins. Filters are bounded to 1,024 patterns per list,
64 KiB per pattern and 1 MiB total pattern text per list.

Downloads check caller-available disk space before preallocating a fresh staging
file, then publish after final on-disk MAC verification. The space check is not a
reservation: another operation can still consume space afterward; write errors
remain failures, never successful partial files.
Resume validates stored identity/coverage and rereads staged chunks; changed
local bytes are not trusted just because a state document says they completed.
Existing unrelated destinations receive unique names. `--overwrite`/`--force`
explicitly allows replacement. `--no-verify` reduces integrity assurance and
should not be used to conceal a MAC mismatch. Complete chunk coverage is required
in both modes; disabling MAC verification never turns cancellation or an incomplete
transfer into a successful file.

Press `p` to pause/resume an interactive transfer; Ctrl+C cancels. JSON/piped
commands do not start a raw keyboard listener. Selection accepts `all`, `none`
or ranges such as `1,3-5`; EOF skips the folder cleanly, with an explanation and
no traceback. Human selection prompts use stdout; in JSON mode they use stderr
so stdout remains JSONL. A glob filter matching no files is a transfer failure,
not a skip: exit 1, with one failed folder summary (`transfer_failed`).

For stored-account-backed public downloads:

```bash
mb download 'https://mega.nz/file/ID#KEY' --account main
```

Authentication failure for an explicitly chosen account is not anonymous success.

Definitive metadata quota rejections keep the configured total attempt budget.
An available proxy pool permits one immediate retry; otherwise the wait can end
early when the kernel-selected local IPv4 address changes. An unavailable route
observation does not shorten the wait. This local observation sends no datagram,
performs no DNS lookup and contacts no external IP-check service. Requests still
obey explicit/forced proxy policy. CDN responses `403`, `410` and `509` refresh an
expired ticket within the bounded chunk retry budget; `404` is a normal refusal,
not permission to refresh. Ticket expiry never counts as proxy failure.

## Accounts and uploads

```bash
mb account add me@example.com --label main --default
```

The account password, vault passphrase and MFA code are prompted locally only in
an interactive human command. Piped/closed-input and JSON commands refuse missing
secrets with the required `--password`, `--vault-passphrase` or `--mfa-code` flag;
JSON commands never start a hidden secret prompt. The vault passphrase must not be
empty. Never paste credentials into a bug report. The native vault/session format is
fresh; it does not read, migrate or erase Python-era stores. Credentials must
be added again after verified replacement.

```bash
mb upload archive.zip --account main --share
```

```bash
mb upload Photos --keep-structure --target Backups
```

```bash
mb account refresh-all
```

```bash
mb upload LargeFiles --auto-account -P 2
```

Automatic selection reserves free quota per file; an entire structured tree stays
on one account. Structured uploads attempt independent siblings after an ordinary
item failure and preserve successful files. Without `--keep-going`, an aggregate
transfer failure is returned after traversal; with it, the partial-result path
still ends nonzero. Cancellation or an unknown remote mutation stops immediately.
A held-file identity and full SHA-256 check protect upload finalization, including
zero-byte files. Unknown remote registration is not replayed. Retained confirmed
receipts support local retry without registering the same upload twice.

Image/video/audio uploads attempt encrypted media thumbnails automatically.
Built-in image support needs no Python/Pillow. Video/audio needs a usable
`ffmpeg` plus sibling `ffprobe`; set `MEGABASTERD_FFMPEG` to the selected path.
Hardware-assisted decode is requested first, with a bounded CPU fallback and an
explicit warning. A requested GPU path is not proof hardware was actually used.
Attachment/share/hook warnings do not undo a successful remote file upload.
JSON results carry independent `thumbnail.status` (`attached`, `not_applicable`,
or `failed`) and any attachment warning/error code. Structured retries retain
confirmed parent/file receipts and do not repeat completed file finalization;
an uncertain prior side effect requires reconciliation rather than replay.

Account precedence is explicit `--account`, then vault default, then configured
`default_account`. `account logout` ends sessions but keeps credentials;
`account remove` removes a stored account/local session with confirmation.
Stored sessions are encrypted. A network error is not permission to erase them.
A verified duplicate signs in and refreshes only its session; it does not replace
stored credentials, labels, quota or the default account. `--no-verify` duplicates
remain errors. After an authentication rejection, `Add account anyway?` defaults
to no; declining or closed input leaves accounts/sessions unchanged. Explicit yes
stores an unverified account, never an authenticated session. Cancellation and
transport failures do not become consent.

A valid cached session is checked before reuse; a definitively expired session is
removed before a fresh login. If only the cache cannot be decrypted with the supplied
vault passphrase, normal account authentication is attempted without deleting that
file. The stored account credential must still decrypt successfully. Corrupt/newer
cache documents and failed network probes stop the command instead of triggering
an unproven fallback or erasing saved data.

Session caching is optional: a failed cache write warns that the next command may
need another sign-in, but does not invalidate a successful login or transfer.
The CLI reports `session refreshed` only after a successful cache write. Corrupt,
future-version, foreign or wrong-passphrase session files are preserved rather
than silently replaced; inspect them before taking an explicit recovery action.

Explicit `account logout` is different from passive session reuse: it sends `sml`
with the cached session directly, without signing in or probing first. With no
cached session it succeeds without asking for the vault passphrase. A definitive
MEGA rejection or wrong-passphrase cache produces a warning and removes only the
local session file; it does not claim that remote logout succeeded. Corrupt or
future-version documents and uncertain remote outcomes are preserved. Cancellation
before sending returns 130; an in-flight logout with no definitive answer is an
unknown mutation (exit 1), not a safe invitation to retry. Stored credentials stay
untouched in every logout outcome.

## Cloud operations

```bash
mb mkdir 'Camera Roll' --parent Backups
```

```bash
mb ls Backups
```

```bash
mb search invoice
```

```bash
mb import 'https://mega.nz/folder/ID#KEY' --target Backups
```

`mv`, `rename`, `rm`, `share` and `trash empty` affect real account data.
Check the selected account and target before confirming. `trash empty` is
permanent remote deletion. Definitive individual failures preserve successful
sibling changes and return a partial/nonzero result. An ambiguous mutation
requires inspecting actual remote state, not automatically repeating the command.

## Streaming

```bash
mb stream 'https://mega.nz/file/ID#KEY' --port 8080
```

The default address is `http://127.0.0.1:8080/`. A player can request full,
open-ended or suffix byte ranges; upstream Range/Content-Range framing is
validated before decryption. This does not download the entire file first.

Non-loopback binding requires a token. Supply it explicitly, or read the generated
token from the private native data location the CLI reports. The token itself is
not logged. Send `Authorization: Bearer <token>`. Query tokens are disabled unless
`--allow-query-token` is explicitly selected because URL history/logs can leak them.
Ctrl+C cancels the server and joins owned clients/workers.

## Proxy pool

```bash
mb proxy import proxies.txt
```

```bash
mb config set smart_proxy_enabled true
```

```bash
mb config set force_smart_proxy true
```

The pool reloads local edits during long operations while retaining matching
health/cooldown state. A failed reload preserves the last usable pool. Explicit
`--proxy` remains an invocation-level choice; forced mode never silently connects
directly after proxy failure. TLS checks remain enabled through tunnels.

`proxy test` checks TCP reachability, not proxy protocol correctness, privacy or
trust. It includes saved and configured proxy URLs, even before Smart Proxy is
enabled. Results show `yes`/`no` with latency or a safe failure reason. Probes use
`timeout_seconds`, at most 64 workers, and a whole-run budget of one timeout per
worker wave; a configured `HOOKMAKER_MAX_TEST_WORKERS` lowers that worker ceiling.
Unstarted entries are distinguished from probes that did not answer in time.

`proxy fetch` contacts the selected public source; assess it before use.
Fetch accepts HTTPS endpoints without embedded credentials, caps decoded lists at
4 MiB and imports only complete lines when truncated. A failed source does not
discard another source's successful result. Diagnostics identify the source host
and a stable error code, never its credentials, query or response body. Ctrl+C
returns 130 without merging fetched entries. The merge reloads current saved data
under its lock, so updates made during the network request are retained.

`proxy serve` is an authenticated loopback service restricted to MEGA domains.
`--any-port` does not make it a general-purpose open proxy.

## Queue and clipboard

```bash
mb queue add-download 'https://mega.nz/file/ID#KEY' -o downloads
```

```bash
mb queue add-upload archive.zip --account main
```

```bash
mb queue run
```

Queue payloads are encrypted; jobs are claimed under cross-process locks and
lease generations. A live owner's heartbeat cannot be stolen by a stale writer.
Failed jobs require explicit `queue retry ITEM_ID` or `queue retry all`.
Ambiguous remote changes remain for reconciliation rather than blind replay.

```bash
mb watch -o inbox
```

The watcher requires a real graphical clipboard backend: PowerShell on Windows,
`pbpaste` on macOS, `wl-paste`/`xclip` on Linux. It queues newly copied links;
`--run` additionally executes the queue. No background service is installed.

## Local file operations

```bash
mb crypter encrypt archive.zip archive.zip.mbcr
```

```bash
mb crypter decrypt archive.zip.mbcr restored.zip
```

```bash
mb split large.iso 500 -o parts
```

```bash
mb merge parts/large.iso.part1-10 -o restored.iso
```

```bash
mb thumbnail picture.png thumbnail.jpg
```

Encryption writes authenticated MBCR v2 with bounded chunks. Legacy v1 decrypt
warns about weaker ordering/trailing-data guarantees. Split/merge uses SHA-1 for
accidental corruption checking, not sender authenticity. `--delete-parts` is
explicit; it is not the default. Existing split parts/checksums and merge outputs
require replacement confirmation; Enter, `n` or closed input leaves them unchanged.
Accepted replacement still refuses input aliases and publishes each completed output
atomically. Merge retains an open handle for every input until verification and
publication, with at most 10,000 parts. On Unix it may raise only its own soft
open-file limit, within the existing hard limit, to accommodate those pinned
inputs and directory anchors. Estimated extra capacity is capped at that hard
limit so it does not unnecessarily reject a small merge. It never changes a
system setting or lowers the limit afterward. A hard limit below the part count
or a rejected adjustment fails before opening parts or creating output; use larger
split parts or start the process with a sufficient limit. Actual directory anchors
and other concurrent descriptor use can still cause an I/O failure; this check is
not an exclusive descriptor reservation. Thumbnail
enlargement is not performed.

DLC/ELC/MegaCrypter resolution contacts external services; local file encryption
is separate and does not make those services trusted. MegaCrypter underlying-link
resolution tries `info`, `openlink`, then `dl`, at most once each. An unsupported
`openlink` (HTTP 404/405/501) does not discard usable metadata. Download/info/stream
share this resolver; a validated temporary download URL is reused rather than
requested again. Passwords and password-derived decryption keys stay local.
Routing refusals, unsafe destinations, cancellation and transport failures are
not invitations to bypass the selected route or silently retry another method.

Service redirects retain the POST body, revalidate each destination and reselect
the configured route, with a maximum of five redirects. A returned MegaCrypter
download URL must pass the shared HTTPS/public-address policy before it reaches a
downloader or streaming consumer; DNS answers are validated again when connecting.
These native paths still require the CI/runtime verification described above.

## Storage and diagnostics

Defaults: `Output/` and `User/native-v2/` beside the native executable. Use a
writable application directory. `MEGABASTERD_PROJECT_ROOT` changes the root;
`MEGABASTERD_USER_DIR` selects a base with `native-v2` appended;
`MEGABASTERD_LOG_DIR` selects the log directory directly.

```bash
mb config path
```

```bash
mb config set max_workers 8
```

See [CONFIG.md](CONFIG.md) for the versioned envelope and validated settings.
Corrupt/newer stores are preserved and refused, not silently replaced. Do not
remove user data merely to resolve a runtime or installation issue.

File logs use unique UTF-8 UTC filenames and structured sanitized records.
`-v`/`-vv` change console diagnostic level; quiet console messages still reach
the file logger. Current-run rotation is not a global log cleanup policy. Review
and redact logs before sharing; never attach credentials, session/queue stores
or private keys. `download --json`/`upload --json` emit JSONL, `info --json` one
JSON object; human diagnostics go to stderr.

| Exit | Meaning |
| --- | --- |
| 0 | Success or explicit skip. |
| 1 | Operation failure, including unknown remote mutation. |
| 2 | Invalid arguments/input. |
| 130 | Cancellation. |

## Validation scope

CI uses synthetic accounts and bounded local TLS peers, independent cryptographic
vectors, real small media files and filesystem/process fixtures. It does not use
personal MEGA accounts or publish signed binaries. Review the native CI results
for the exact commit you install. Existing Python-era user data remains untouched;
see [migration notes](MIGRATION.md) before changing installations.
