# Native Configuration Reference

The Rust implementation uses **fresh, versioned native storage**. It does not read or
rewrite Python-era configuration/accounts/queues. This reference describes
the native storage and command behavior checked in CI.

```bash
mb config path
```

## Location and format

By default the configuration is
`<native-executable-directory>/User/native-v2/Config/config.json`.
`MEGABASTERD_PROJECT_ROOT` changes the application root;
`MEGABASTERD_USER_DIR` selects the base user directory with `native-v2` appended.
The CLI should run from a writable installation directory. A configured relative
file path is resolved relative to the caller's CWD unless the relevant command
specifies otherwise; the default application data paths are independent of CWD.

Stores use an envelope, not a bare settings object:

```json
{"version":2,"data":{"max_workers":8,"verify_integrity":true}}
```

Prefer `config set` to hand edits. The store serializes under a persistent sidecar
lock, reloads the latest value, writes a private same-directory stage, flushes,
syncs and atomically replaces. Lock files remain intentionally. Permissions,
path aliases and unsupported filesystem behavior are validated, not bypassed
through an insecure reopen. Final replacement makes at most five attempts for
permission refusals or Windows sharing/lock violations, with 50/100/150/200 ms waits.
The same stage, directory anchor and sidecar lock remain owned until completion.
Other failures are returned immediately; failed replacement removes only its
stage and preserves the original error unless staging cleanup itself fails.
A successful rename is never replayed after a directory-sync failure.

## Commands and validation

| Command | Meaning |
| --- | --- |
| `mb config show` | Sanitized effective settings. |
| `mb config get KEY` | Sanitized one-setting display. |
| `mb config set KEY VALUE` | Validate and persist a setting without echoing its value. |
| `mb config unset KEY` | Clear a nullable setting. |
| `mb config reset` | Confirm default reset; refuses corrupt data. |
| `mb config path` | Active path. |
| `mb config migrate` | Normalize supported native settings and remove retired/unknown keys; no old-data import. |
| `mb config recover` | Report corruption without mutating it. |
| `mb config recover --reset` | Confirm preserving original bytes and restoring defaults. |

Booleans accept `true/false`, `1/0`, `yes/no`, `on/off`. Numeric fields reject
booleans. Nullable strings accept `null`/`none`; an ordinary string is not cleared
just because it contains those characters. `elc_accounts` accepts a JSON object
of host → object of string values.

Unknown/retired keys cannot be set. Invalid known values in an otherwise valid
native settings object produce sanitized warnings and use their default.
Unknown keys are ignored with warnings. Command contexts report each ignored key
at most once per process; invalid known values still report their repair on every
load. Unknown key names and secret values are never echoed. Warning history keeps
at most 4096 key digests; exceeding that bound blocks normal commands until stale
settings are removed and the process is restarted.
`config migrate` normalizes only a supported native envelope under the same lock:
retired/unknown settings are removed, valid values are retained, and invalid known
values use their validated defaults. A second call does not rewrite unchanged
settings. It does not import Python-era or unsupported-format documents. The old
built-in `MegaBasterd-CLI/1.0` User-Agent normalizes to empty, selecting the current
version-derived default; custom User-Agents remain unchanged.

Malformed UTF-8/JSON, duplicate object keys (including escaped spellings and
nested objects), unsupported envelope/root/data shapes and future versions are
corruption, not a reason to overwrite with defaults. Every non-`config`
command refuses before prompting, contacting a service or changing command data;
read-only configuration display may show defaults with a warning. Config mutations
also refuse until explicit recovery. Detecting damaged data attempts one private
`config.json.corrupt-<sha256>` recovery copy per distinct content under the same
sidecar lock. Repeated reads reuse a copy only after verifying its exact bytes;
a copy failure is reported without changing the original. If another operation
holds the lock, a bounded private snapshot may diagnose corruption but cannot
supply usable settings, create a copy or authorize a mutation. Explicit recovery
verifies the preserved copy before replacing damaged data with defaults. A future
version is not reset. Keep recovery copies until recovery is verified.

## Transfer settings

| Key | Default | Meaning |
| --- | --- | --- |
| `download_path` | `""` | Empty selects application-root `Output/`; `config get/show` displays that effective path. |
| `max_workers` | `8` | Download chunk workers, 1–64. |
| `upload_workers` | `4` | Upload chunk workers, 1–64. |
| `max_parallel_downloads` | `6` | Parallel download files, 1–32. |
| `max_parallel_uploads` | `1` | Parallel upload files, 1–32. |
| `speed_limit_kbps` | `0` | Aggregate download KiB/s, finite/nonnegative; 0 unlimited. |
| `upload_speed_limit_kbps` | `0` | Aggregate upload KiB/s, finite/nonnegative; 0 unlimited. |
| `verify_integrity` | `true` | Final on-disk download MAC verification. |
| `timeout_seconds` | `60` | Positive HTTP timeout. |
| `auto_resume` | `true` | Reuse compatible validated native transfer state. |
| `keep_state_files_on_error` | `true` | Retain failed-download state/staging for recovery. |
| `quota_wait_seconds` | `3600` | Maximum wait between definitive quota-rejected metadata attempts; 0 disables recovery. |
| `quota_max_wait_loops` | `24` | Total metadata attempts, including the first; 0 or 1 permits only one attempt. |

MEGA chunk sizes are protocol-defined. `chunk_size_kb` is retired as a download
setting; `crypter encrypt --chunk-size-kb` is a separate local-file parameter.
Corrupt/foreign/future state is preserved rather than reused. Upload state whose
source changed after sending is discarded only while known unregistered;
ambiguous-registration markers/confirmed receipts are never cleared by that path.

## Account and listener settings

| Key | Default | Meaning |
| --- | --- | --- |
| `default_account` | `null` | Fallback only after explicit selection and the vault default. |
| `streaming_port` | `8080` | Stream port, 1–65535. |
| `streaming_host` | `"127.0.0.1"` | Stream bind host; non-loopback requires access token. |
| `connect_proxy_port` | `9999` | Loopback proxy port, 1–65535. |
| `connect_proxy_password` | `null` | Local proxy authentication password; redacted in displays. |
| `connect_proxy_allow_any_port` | `false` | Broaden ports, not the MEGA-domain boundary. |

Account passwords/sessions belong in the encrypted vault/session store, not
ordinary config. `MEGABASTERD_VAULT_PASSPHRASE` is a supported noninteractive
unlock input; keep it out of logs, history and support attachments. Native
configuration is permission-restricted, not a universal encrypted secret store.

## Routing and containers

| Key | Default | Meaning |
| --- | --- | --- |
| `smart_proxy_enabled` | `false` | Enable rotating local proxy pool. |
| `smart_proxy_url` | `null` | Configured proxy URLs, split on whitespace/comma/semicolon. |
| `force_smart_proxy` | `false` | Refuse direct fallback when no valid proxy is selected. |
| `megacrypter_server` | `null` | Server for `crypter make-link`. |
| `elc_accounts` | `{}` | Host-specific string-valued ELC credentials; recursively redacted. |

Pool data reload is bounded and local; it is not a remote proxy crawler or an
automatic background refresh service. Explicit `--proxy` remains explicit.
`smart_proxy_autorefresh_minutes`, `smart_proxy_timeout_seconds` and
`smart_proxy_random` are retired; use real supported command options instead.
TLS/DNS/public-address/redirect rules apply to API calls, CDN, link services and
attribute transfers; forced mode must not be worked around by another adapter.

## Logging and post-transfer commands

| Key | Default | Meaning |
| --- | --- | --- |
| `log_level` | `"WARNING"` | Console diagnostic threshold: DEBUG/INFO/WARNING/ERROR/CRITICAL. |
| `log_to_file` | `true` | Private per-run file logging, overridable by root flags. |
| `log_max_bytes` | `5000000` | Current-run rotation threshold. |
| `log_backups` | `5` | Current-run rotated segment limit. |
| `user_agent` | `""` | Empty selects `MegaBasterd-CLI/<version>`. |
| `run_command` | `null` | Optional per-file local command; path appended as one literal argument. |
| `all_finished_command` | `null` | Optional once-per-nonempty-batch command; kind/succeeded/failed arguments. |
| `upload_log_path` | `null` | Optional sanitized JSONL upload-result log. |

`-v`/`-vv` select INFO/DEBUG console diagnostics; `--quiet` suppresses ordinary
console messages. File entries are independent of console filtering. Logs use
UTF-8, unique `mb_YYYY-MM-DD_HH-mm-ss_UTC.log` names and UTC
`[timestamp] [LEVEL] [COMPONENT] Message` records with sanitized structured fields.
Set either rotation value to 0 to disable rollover. Rotation affects only this
run's base/numbered segments; earlier operational logs are not deleted. Default
log location is `<user-base>/native-v2/Logs/`; `MEGABASTERD_LOG_DIR` overrides it
directly. A write/init failure produces a safe console warning, not a false log
creation claim.

Post-transfer command strings are trusted local configuration, parsed into an
executable/argument vector, never run through a shell. INFO diagnostics identify
only the executable basename and configured-argument count, not argument values,
appended file paths or child output. Output is bounded; cancellation/timeouts own
the child tree. The application does not install hooks or services.
Hook/share/thumbnail errors are separately reported after upload.

## Native runtime files

| Native path under `User/native-v2/` | Contents |
| --- | --- |
| `Config/config.json` | Versioned settings. |
| `Data/accounts.json` | Account records with encrypted passwords. |
| `Data/sessions/` | Encrypted cached sessions. |
| `Data/queue.json` | Encrypted queue payloads and job state. |
| `Data/proxies.json` | Stored pool URLs. |
| `Data/transfers/` | Native download/upload state and receipts. |
| `Logs/` | Default diagnostic logs. |

Account documents reject malformed roots, unknown fields, ambiguous email/label
identifiers, invalid quota types/ranges and malformed encrypted credential envelopes
before mutation. Account labels are matched without regard to case. A damaged
account document is kept unchanged, with one private `accounts.json.corrupt-<sha256>`
recovery copy per distinct content when that copy can be written and verified.
A failed backup is reported; it never authorizes replacing the original vault.
Proxy documents likewise require an object with a URL-string list, reject unknown
fields and preserve corrupt bytes before mutation. Their private recovery copies
use `proxies.json.corrupt-<sha256>` with the same exact-byte verification policy;
a damaged store is not permission to silently clear the proxy routing policy.

Preserve these as user/application data. Old-runtime cleanup never authorizes
removing credentials, outputs, queue data or operational logs. The native
storage uses its own native format; old personal stores are never overwritten.
