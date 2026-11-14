# Rust 2.x migration

The native version continues `refactor/rust-cli-rewrite` at
`b3c6933`, based on source baseline `ac8347d`. These are the identity-repaired
counterparts of `6eb6155` and `c4559ec`, with identical source trees. Frozen
fixture provenance retains the original generation IDs. The executable commands and
55 command leaves are preserved. Application code, tests, packaging and the CI
driver now use Rust. YAML/TOML/JSON files are configuration or test data. CI-only
Python compares immutable historical function bodies, and isolated PowerShell scripts
sign release artifacts; neither is an application runtime bridge.

## User data

Native data lives under `User/native-v2/` (or the configured user directory plus
`native-v2`). Existing Python-era accounts, sessions, configuration, queues and
partial transfers are not read or overwritten. Re-add accounts and configure the
native installation explicitly. `config migrate` normalizes native settings; it
does not import old personal stores. Keep the old installation/data separately if
you need to finish an existing transfer.

The native vault uses authenticated, versioned envelopes with bounded scrypt
parameters. Queue source URLs, destinations, account selection, passwords and
errors are all encrypted. Completed resume coverage requires a chunk MAC and a
matching source identity. Invalid/future saved documents are preserved and cause
an explicit refusal; recovery does not silently overwrite them or replace keys.
Unsafe existing log permissions are refused rather than repaired in place.

## Interface adaptations

Python import aliases, Rich objects, .NET helpers and PowerShell entrypoints are
replaced by Rust modules, typed values, native processes and the shared logger.
MD5 compatibility file checksums remain available as a Rust helper. CLI errors
use `0` for success, `1` for operation failure, `2` for invalid usage and `130` for
cancellation. An explicit proxy takes precedence over an automatic pool. Proxy
list source URLs containing credentials are refused before contact. Rate limits
are immutable during an individual transfer; new settings apply to new transfers.

## Tests

`tests/fixtures/contract_coverage.json` retains 1,416 original test identities from
164 modules. Every identity has a named Rust assertion mapping and an explicit
reason for any changed language/storage mechanism. No case is retired or waived.
Native functions can group several related original assertions, so 1,416 is the
preserved source-contract denominator, not a claim that libtest and pytest
collect the same number of parameter-expanded test cases. Independent vectors
and bounded network/process/filesystem fixtures remain part of the suite.

`cargo xtask verify` verifies source digests, discovers every native test, checks
that all discovered tests passed, and only then reconciles applicable mappings.
The exact commit, target architecture and all case dispositions are recorded in
a CI artifact. Formatting, static types/Clippy, dependency policy and the prior
76% line-coverage gate remain separate checks. Release binaries are always built
in CI on Linux, Windows, macOS Intel and macOS Apple Silicon.

## Other branches

The migration preserves the Rust checkpoint in its ancestry. The old Python
Black-update proposal does not apply to the native application. Branch cleanup
must preserve unique or unverified work; removing a runtime does not authorize
deleting unrelated branches or historical source.
