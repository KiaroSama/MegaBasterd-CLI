# MegaBasterd CLI

A native Rust command-line client for MEGA.nz downloads, uploads, public links,
cloud files, encrypted queues, proxies, streaming and local file tools. Inspired
by [MegaBasterd](https://github.com/tonikelope/megabasterd); no desktop GUI or
Python runtime bridge is included in the native implementation.

<div align="center">

[![Rust CI](https://github.com/KiaroSama/MegaBasterd-CLI/actions/workflows/ci.yml/badge.svg)](https://github.com/KiaroSama/MegaBasterd-CLI/actions/workflows/ci.yml)
[![Coverage](https://github.com/KiaroSama/MegaBasterd-CLI/actions/workflows/tests.yml/badge.svg)](https://github.com/KiaroSama/MegaBasterd-CLI/actions/workflows/tests.yml)
[![Dependency audit](https://github.com/KiaroSama/MegaBasterd-CLI/actions/workflows/audit.yml/badge.svg)](https://github.com/KiaroSama/MegaBasterd-CLI/actions/workflows/audit.yml)
[![License GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-238636)](LICENSE)
[![Rust edition 2024](https://img.shields.io/badge/Rust-edition%202024-238636)](Cargo.toml)
[![Rust toolchain 1.99.1](https://img.shields.io/badge/Rust-1.99.1-238636)](rust-toolchain.toml)
[![Interface native CLI](https://img.shields.io/badge/Interface-native%20CLI-238636)](#all-commands)
[![CLI parser clap](https://img.shields.io/badge/CLI-clap-238636)](Cargo.toml)
[![TLS implementation rustls](https://img.shields.io/badge/TLS-rustls-238636)](Cargo.toml)
[![Local encryption AES-GCM](https://img.shields.io/badge/Local%20encryption-AES--GCM-238636)](docs/ARCHITECTURE.md)
[![Vault KDF scrypt](https://img.shields.io/badge/Vault%20KDF-scrypt-238636)](docs/ARCHITECTURE.md)
[![Source fingerprints SHA-256](https://img.shields.io/badge/Source%20fingerprints-SHA--256-238636)](docs/ARCHITECTURE.md)
[![Machine output JSONL](https://img.shields.io/badge/Machine%20output-JSONL-238636)](docs/COMMANDS.md)
[![Documentation command reference](https://img.shields.io/badge/Docs-command%20reference-238636)](docs/COMMANDS.md)
[![Support donations](https://img.shields.io/badge/Support-donations-d04a9a)](#donate)

</div>

The application, tests and CI driver are implemented in Rust. The three native
commands are `mb`, `mbcli` and `megabasterd-cli`. No interpreter or script launcher
is required. CI builds Linux x64, Windows x64, macOS Intel and macOS Apple Silicon
on every push and pull request.

## Installation

Download the artifact matching your OS and architecture from a successful
[Rust CI run](https://github.com/KiaroSama/MegaBasterd-CLI/actions/workflows/ci.yml).
Each artifact contains the three command aliases, `SHA256SUMS`, license notices
and the matching Rust source package. Extract the commands together, verify the
checksums and add the directory to `PATH`. Build artifacts are unsigned;
[Releases](https://github.com/KiaroSama/MegaBasterd-CLI/releases) is the destination
for published versions.

```bash
mb --version
mb --help
```

### Build from source

Install Rust **1.99.1** and a native linker: MSVC Build Tools on Windows, Xcode
Command Line Tools on macOS, or a C toolchain on Linux for native dependencies.
`rust-toolchain.toml` pins Rust; `Cargo.lock` pins dependencies.

```bash
cargo build --locked --release --bins -p megabasterd-cli
```

Binaries are written to `target/release/` (`.exe` on Windows). A compiler is needed
only when building from source. See [CONTRIBUTING.md](CONTRIBUTING.md) for testing,
coverage and packaging commands.

### Optional integrations

Image thumbnails use the built-in image decoder. Video/audio thumbnails require
an independently installed `ffmpeg` and matching sibling `ffprobe`, with seekable
`fd` input from inherited regular-file stdin on the selected native platform. Set `MEGABASTERD_FFMPEG` to the
chosen executable path, or make the tools available on `PATH`. The application
never installs media tools automatically. Missing media support is a separate
warning after an otherwise successful upload, not proof the upload failed.

Clipboard watching uses PowerShell `Get-Clipboard` on Windows, `pbpaste` on
macOS, or `wl-paste`/`xclip` on Linux. A usable graphical clipboard session is
required; a headless host need not have one.

## Usage

After installing a native binary:

```bash
mb --help
```

```bash
mb info 'https://mega.nz/folder/ID#KEY' --json
```

```bash
mb download 'https://mega.nz/folder/ID#KEY' -I '*.mkv' -X '*sample*' -o downloads
```

```bash
mb account add me@example.com --label main --default
```

```bash
mb upload archive.zip --account main --share
```

`ID` and `KEY` above are format placeholders, not working test links. Public
`info` does not need an account or MFA and never downloads file content.
Running `mb` without arguments opens the native menu in an interactive terminal;
noninteractive input must not wait for hidden prompts. Press `p` to pause/resume
interactive transfers, or Ctrl+C to cancel. JSON/piped transfers do not start
the keyboard listener.

## All commands

The native schema retains **55 leaf commands: 16 root commands and 39 commands
inside six groups**. All are listed below; see [the option reference](docs/COMMANDS.md)
for flags, defaults and limitations. Append `--help` to any command for its
actual executable help.

### Transfers, public links and cloud files

| Command | Purpose |
| --- | --- |
| `mb download [URL ...]` | Download files, folders, containers or an input link list. |
| `mb upload PATH ...` | Upload files/directories using stored accounts. |
| `mb stream URL` | Serve decrypted ranges through a local authenticated HTTP endpoint. |
| `mb info URL` | Inspect a public link, including a folder file list with `--json`. |
| `mb share TARGET` | Create, password-wrap or remove a public link. |
| `mb ls [PATH]` | List account files or the entire node listing. |
| `mb mkdir NAME` | Create a cloud folder. |
| `mb rm TARGET` | Request removal of a cloud node; confirmation unless `--yes`. |
| `mb mv SOURCE DESTINATION` | Move a cloud node into a folder. |
| `mb rename TARGET NEW_NAME` | Rename a cloud node. |
| `mb search PATTERN` | Search cloud names, optionally using a regular expression. |
| `mb import SHARE_URL` | Import a public folder share server-side. |
| `mb trash list` | List trash children. |
| `mb trash empty` | Permanently remove trash children, with confirmation. |

### Accounts and queue

| Command | Purpose |
| --- | --- |
| `mb account list` | List stored account identities. |
| `mb account add EMAIL` | Store encrypted credentials and optionally verify/login. |
| `mb account remove EMAIL_OR_LABEL` | Remove a stored account and its session. |
| `mb account logout [EMAIL_OR_LABEL]` | End cached sessions; `--all` selects all accounts. |
| `mb account default EMAIL_OR_LABEL` | Set the account-vault default. |
| `mb account info [EMAIL_OR_LABEL]` | Read account details/quota. |
| `mb account refresh-all` | Refresh stored account quotas. |
| `mb queue list` | Inspect queued job status. |
| `mb queue add-download URL` | Queue a download. |
| `mb queue add-upload PATH` | Queue a local file upload. |
| `mb queue remove ITEM_ID` | Remove a queued job. |
| `mb queue retry ITEM_ID` | Return an eligible failed/interrupted job to pending; accepts `all`. |
| `mb queue clear` | Clear finished queue items. |
| `mb queue reset` | Explicitly reset queue data with confirmation. |
| `mb queue run` | Claim and execute queued jobs under leases/heartbeats. |

### Proxies and link/file encryption

| Command | Purpose |
| --- | --- |
| `mb proxy list` | List pooled proxies and optionally configured URLs. |
| `mb proxy add URL ...` | Add validated proxy URLs. |
| `mb proxy remove URL` | Remove a pooled proxy. |
| `mb proxy clear` | Clear the stored proxy pool. |
| `mb proxy import PATH` | Import proxy URLs from a local text file. |
| `mb proxy fetch` | Fetch a bounded proxy list from an explicit/default source. |
| `mb proxy test` | Test TCP reachability, not end-to-end proxy trust or correctness. |
| `mb proxy serve` | Run an authenticated loopback MEGA-domain CONNECT/HTTP proxy. |
| `mb crypter encrypt SOURCE DESTINATION` | Encrypt a local file with the MBCR authenticated format. |
| `mb crypter decrypt SOURCE DESTINATION` | Authenticate and decrypt MBCR data. |
| `mb crypter make-link MEGA_URL` | Ask the configured MegaCrypter service to create a link. |
| `mb crypter resolve MC_URL` | Resolve a supported MegaCrypter link. |
| `mb crypter elc-resolve ELC_URL` | Resolve an ELC container with the selected credentials. |
| `mb crypter dlc-resolve PATH` | Resolve a local DLC container through the trusted DLC service. |

### Local tools and settings

| Command | Purpose |
| --- | --- |
| `mb split SOURCE PART_SIZE_MB` | Split a file into numbered parts and a SHA-1 sidecar. |
| `mb merge ANY_PART` | Reassemble parts, verifying SHA-1 unless explicitly disabled. |
| `mb thumbnail SOURCE DESTINATION` | Produce an aspect-preserving JPEG, bounded by 250x250. |
| `mb watch` | Watch the clipboard and queue newly copied MEGA links. |
| `mb config show` | Display settings with secret fields redacted. |
| `mb config get KEY` | Display one setting. |
| `mb config set KEY VALUE` | Validate and persist one setting. |
| `mb config unset KEY` | Clear a nullable setting. |
| `mb config reset` | Restore defaults with confirmation. |
| `mb config path` | Print the active configuration path. |
| `mb config migrate` | Normalize current native settings and remove retired keys; no Python data import. |
| `mb config recover` | Inspect corruption; `--reset` explicitly preserves then resets it. |

Global flags: `-h/--help`, `--version`, repeatable `-v/--verbose`, `-q/--quiet`,
`--log-file` and `--no-log-file`. For portable scripts, put root options before
the command. `--version` has no `-V` alias.

## Transfer behavior and safety

- Downloads use MEGA chunk sizes, staged output, resume validation and final disk
  MAC verification by default. Unrelated destinations get a unique name;
  `--overwrite`/`--force` explicitly permits replacement. `--no-verify` disables
  the final MAC check and reduces integrity assurance.
- Uploads hash the entire source and check the held file identity before remote
  registration. Completion receipts prevent blindly replaying registration after
  an interrupted local finalization. Unknown remote mutations are not retried.
- Speed limits are aggregate per command. Automatic account selection reserves
  quota per file; a structured tree stays on one account. Public downloads can
  explicitly use a stored account. Independent disk verifications share a permit.
- The proxy pool can reload local changes during a command. Forced proxy mode
  never silently falls back to direct traffic. Remote endpoints retain TLS
  certificate/hostname checks and public-address restrictions.
- Cloud mutations and `trash empty` affect real remote data. Partial batches
  preserve successful changes and report nonzero failure, not an all-success
  message. Use only content and accounts you are authorized to access.

DLC resolution contacts JDownloader's public service over HTTPS. MegaCrypter/ELC
resolution contacts the selected service; consider that service's trust and data
handling before sending links or credentials. Local encryption does not make an
untrusted external resolver safe.

## Data, output and logging

Defaults are relative to the native executable directory, not the caller's CWD.
Choose a writable installation directory or configure explicit locations.

| Location | Contents |
| --- | --- |
| `Output/` | Default download destination. |
| `User/native-v2/Config/config.json` | Versioned native configuration. |
| `User/native-v2/Data/` | Native vault, sessions, encrypted queue, proxy pool and transfer state. |
| `User/native-v2/Logs/` | Private per-run diagnostic logs. |
| `*.mbclaim` | Persistent advisory reservation sidecars; intentionally not unlinked. |

`MEGABASTERD_PROJECT_ROOT` overrides the application root. `MEGABASTERD_USER_DIR`
selects a base directory, with `native-v2` appended. `MEGABASTERD_LOG_DIR` selects
the log directory directly. Native storage does not read or overwrite Python-era
stores. Add accounts afresh; never delete old credentials/data merely to clean up
runtime files.

Logs use UTF-8 and a unique `mb_YYYY-MM-DD_HH-mm-ss_UTC.log` per execution, with
collision suffixes when necessary. Records use
`[YYYY-MM-DD HH:mm:ss UTC] [LEVEL] [COMPONENT] run=<id> cmd=<command> Message`
and sanitized structured context. The run ID is the selected log filename without
`.log`, including any collision suffix; it stays fixed across rotated segments.
The command is a fixed root-command label, never raw arguments. Direct library
logging uses `cmd=unknown`. Levels are DEBUG/INFO/WARNING/ERROR/CRITICAL. `-v` selects INFO console
diagnostics, `-vv` DEBUG; quiet/filtering does not remove diagnostic file entries.
`log_max_bytes` and `log_backups` rotate only the current run's segments; older
operational logs are not automatically deleted. `--no-log-file` explicitly
turns file logging off. Initialization/write failures warn safely. A caught
command-thread panic keeps a bounded, sanitized cause, source location and native
backtrace in the private log; public output stays generic. Abort, double-panic,
worker-thread and unsupported-backtrace recovery are not guaranteed.

JSON modes (`download`, `upload`, `info`) keep stdout machine-readable; human
messages and progress use stderr. Secret fields/link keys are redacted except
an intentionally returned public `share_link`. File logs also mask account email
addresses and MEGA/CDN URLs and wire metadata; console account listings retain
their useful identifiers. Treat logs as private: review and sanitize them before
attaching the relevant run file to a bug report. Never
attach account stores, passwords, MFA codes, session data or queue keys.

Exit codes: `0` success/explicit skip, `1` operation failure, `2` invalid usage,
`130` cancellation. An ambiguous remote mutation is a failure requiring remote
state inspection, not an instruction to repeat it.

## Development and verification

[CONTRIBUTING.md](CONTRIBUTING.md) describes the native CI/tooling boundary.
Rust CI runs formatting, Clippy/type checking, dependency auditing, the native
test matrix and Release builds. The previous 76% line-coverage gate is retained
with LLVM coverage. The assertion ledger retains all **1,416 baseline test
definitions across 164 modules**, including language-specific replacements.
Rust tests combine several related assertions in one test function; the ledger
counts source contracts rather than pretending the two harnesses collect the
same number of parameter-expanded cases. CI verifies every applicable mapping
against tests actually discovered and passed on each platform.

[Upstream changes](docs/UPSTREAM.md) records the reviewed MegaBasterd commit and
which changes are implemented, already present, or specific to its desktop GUI.
[Migration notes](docs/MIGRATION.md) explain the storage and interface changes.

See [commands](docs/COMMANDS.md), [usage](docs/USAGE.md),
[configuration](docs/CONFIG.md), [architecture](docs/ARCHITECTURE.md) and
[security reporting](SECURITY.md).

## License and attribution

New owner-authored Rust code and native tooling are **GPL-3.0-or-later**.
See [LICENSE](LICENSE) and [ATTRIBUTION.md](ATTRIBUTION.md). Earlier MIT grants
remain valid; their notice is retained in
[licenses/MIT-historical.txt](licenses/MIT-historical.txt). Third-party work keeps
its own license. Binary distribution must include the corresponding source and
applicable notices; another commit's source is not a matching source release.

## Donate

If this project helps you, donations are appreciated.

| Currency | Network | Address |
| --- | --- | --- |
| Bitcoin (BTC) | Bitcoin | `bc1qmth5m03pu5hujw5xw5jmywam3jj3sqwqupesdt` |
| USDT, BNB, USDC, etc. | BEP20 | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |
| USDT, TRX, USDC, etc. | TRC20 | `TWBA3xFTqgZAeAYMxqo85xWnzvty3DcAhw` |
| Ethereum (ETH) | ERC20 | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |
| TON | TON | `UQCN8Umo_OfOWqImZetQsrNStPcmLkMAKajFyiCOhso23NDb` |
| Litecoin (LTC) | LTC | `ltc1qntqnnrunadurnw4cshv3qgspywrueyyeyngwuy` |
| Solana (SOL) | Solana | `7B2wkczUjmkDhETwQuknBL8sUsbuV7nErxc317TmQuwR` |
| Polygon (POL) | Polygon | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |
