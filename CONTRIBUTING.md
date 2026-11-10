# Contributing

The native Rust rewrite is a migration candidate. The old Python implementation
remains an offline behavior oracle/recovery version until cutover; it is not a
permitted native runtime bridge. Native compilation, complete parity and release
verification remain pending.

## Native prerequisites

Rust 1.99.1, edition 2024, Cargo.lock and native system linker/SDK are the source
build contract. No automatic global compiler or media-tool installation is part
of the application. Video/audio tests need a verified ffmpeg/ffprobe pair with
seekable `fd` input from inherited regular-file stdin. The hosted workflow must supply
that pair; missing prerequisites are failures, not skipped passing coverage.

The public interface is the CLI (`mb`, `mbcli`, `megabasterd-cli`), not Python
imports. See [README](README.md), [commands](docs/COMMANDS.md),
[configuration](docs/CONFIG.md) and [architecture](docs/ARCHITECTURE.md).

## Development checks

A light edit loop may use formatting/typechecking and a narrowly targeted seam
check. Dependency-heavy local builds/caches are intentionally avoided during the
migration. Release builds and the final native Windows/Linux/macOS Intel/Apple
Silicon matrix run in manually dispatched hosted CI, after the integrated change
is ready. Do not enable automatic push/PR/schedule triggers to get intermediate
runs. A passing old Python job is not Rust evidence.

The manual entrypoint is `.github/workflows/release.yml`, already present on the
default branch. Dispatch it only for the completed candidate ref. It calls
`ci.yml` with `workflow_call` from that exact same commit, without inherited
secrets. This does not require publishing an intermediate workflow bootstrap.
The current workflow performs native validation and a separate full locked-graph
Cargo dependency/license/source audit. After complete native checks each native
job prepares matching project/dependency source archives, verifies their extracted
lockfile and vendored bytes, and rebuilds optimized compiler intermediates with
an initially empty Cargo cache and frozen resolution. It verifies an allowlisted
runtime archive and runs all three relocated aliases with runtime-only variables.
The Windows job also invokes the extracted `Run.ps1` from an unrelated directory
through an installed PowerShell host, checking literal arguments, configuration
location and native exit-code propagation without Python or Cargo on runtime PATH.
These stages remain unexecuted. Unsigned intermediates are not uploaded, signed,
installed or called a completed release; final signing and complete release
packaging remain pending.

```bash
cargo fmt --all --check
```

```bash
cargo clippy --locked --workspace --all-targets -- -D warnings
```

```bash
cargo test --locked --workspace --all-targets --no-fail-fast
```

```bash
cargo test --locked --workspace --doc --no-fail-fast
```

These are native development commands, not a statement that they have already
passed for the candidate. Full runs belong in the bounded CI runner rather than
being repeated locally. The runner supplies shared worker limits, wall/idle/
memory ceilings, contained temporary paths, noninteractive stdin and owned
process-tree cleanup. It checks that Cargo's active suites match files on disk;
ignored/custom/disabled test harnesses need explicit coverage justification.

CI build/test support is Python stdlib tooling (`python -I tools/ci/run-native.py
--target <native-triple> --baseline .ci-work/source-baseline`), not a Python
application dependency. The workflow checks out the exact immutable assertion
baseline separately; its commit and source hashes are verified before AST-only
assertion inspection. The resource comparison also extracts and executes only
selected, complete hashing/split/merge definitions from three hash-verified
baseline files; it never imports the old application or installs its dependencies.
The runner requires Python >=3.11 and hosted Rustup >=1.29.0, verifies the actual native host,
uses locked dependencies and never packages the tooling environment. Tooling
selftests are discovered only under `tools/ci/`; retained application modules are
not imported by them. Their UTF-8 UTC logs are private runtime diagnostics, not
release assets.

The native resource fixture compares upload source hashing and local split/merge
on identical 1 MiB + 17-byte and 16 MiB + 17-byte inputs. Each engine gets three
fresh child processes per size, one worker, a 30-second child deadline and the
runner's outer resource/idle limits. It validates source/output hashes, part
lengths, sidecar bytes and strict sample fields before writing measurements.
Per-target `native-resources-<target>` artifacts contain actual nanosecond timings,
peak resident working-set bytes, min/median/max and native/source ratios, bound to
the candidate commit. They do not contain inputs, filesystem paths or raw logs.
These are debug-harness, warm-cache transfer-preparation measurements, not release
benchmarks or network throughput. Native disk rereads, durability and ownership
checks remain enabled. No relative speedup is required or claimed; the complete
comparison and artifact transport have not run yet.

The separate dependency job acquires only the SHA-256-pinned cargo-deny 0.20.2
Linux tool in an ephemeral hosted work directory. It uses `deny.toml` to check
advisories, licenses (including build/dev dependencies) and crate sources across
the entire locked graph. Unrecognized licenses and audit failures stop the job;
there are no advisory exclusions. This check does not supply the complete
third-party source/notices or prove signed runtime distribution. Native jobs
prepare dependency-source archives with `cargo vendor --locked --versioned-dirs`,
check every file against its package inventory and bind it to the exact lockfile.
The rebuild uses both extracted archives, their portable Cargo source replacement,
the installed pinned compiler and a new empty Cargo home/output tree. Cargo runs
with `--frozen` (locked and offline); this does not isolate build scripts or native
tools from the OS network or prove byte reproducibility. Runtime intermediates
preserve actual root, declared and nested dependency notice files under
`licenses/dependencies/<name>-<version>/`, with original bytes and a package/hash
index. All locked packages are included conservatively, including build/dev/other
target dependencies; this is not an exact linked-code inventory or legal approval.
Missing, empty, unsafe or non-UTF-8 notice files stop preparation rather than being
replaced by generated SPDX templates. Full legal/source completeness, rebuild and
relocation checks remain unverified until reviewed and actual native CI executes.
Neither the audit tool nor a compiler is installed on the user's machine by this
workflow.

## Meaningful tests

Use the actual public seam: parsed CLI, protocol envelope, transfer bytes, native
file transaction, queue ownership or bounded child. Independent source-generated
vectors supply crypto expectations. Do not regenerate expected values from the
Rust function under test or equate a helper test with full command coverage.
Controlled peers use real TLS/framing with isolated public test roots and joined
threads; never disable production TLS/DNS/containment checks for convenience.

The parity ledger accounts for 1,416 **static definitions**, not runtime-expanded
pytest cases. Every mapping names a specific native assertion/seam/variant;
missing mappings remain missing. Structure, accounting and native execution are
separate gates. Final evidence binds target source hashes and all required native
platforms to the exact candidate commit; a written/verified label alone is not
proof. The runner discovers compiled harnesses from Cargo's JSON artifacts,
lists and runs each suite through Cargo once, and matches exact test names from
libtest's separate result file rather than scraping application stdout. The
pinned toolchain supports `--logfile`; changing toolchains requires rechecking
that contract. Only sanitized assertion receipts are transferred between jobs;
raw test output and runtime logs are not uploaded. A final job requires receipts
from Windows, Linux and **both** macOS architectures, with matching repository,
commit, workflow run/attempt and source digests, before the execution gate can
pass. Platform-specific mappings are bounded by verified OS markers in the
immutable source baseline, not by candidate-declared exclusions. Unknown or
dynamic prerequisite markers retain all three OS requirements. Shared native
assertions require the union of their source scopes; each receipt must contain
exactly its applicable references. Windows-only ACL assertions are never replaced
with successful Unix no-ops. All four target receipts remain mandatory. Missing
source assertions still fail even if every native suite passes. Do not weaken
assertions, skip failing tests or mark failures expected merely to obtain green
output.

An intentional retirement also needs an independently supplied owner decision;
editing a ledger label never grants approval. The manual workflow's optional
`retirement_approvals` string accepts JSON with exactly `schema_version` (1),
`baseline_commit`, `commit`, `ledger_sha256` and `approvals`. The digest is SHA-256
of the full ledger serialized as ASCII JSON with sorted keys, no whitespace and
nonfinite numbers forbidden (the `ledger_digest` function in
`tools/ci/retirement_approvals.py`). Each `approvals` key is an exact retired source
test identity; its value contains exactly `action` and `authority`, matching the
reviewed row. Supply the complete retired set, not a blanket category approval.
The candidate commit and immutable baseline must match. Empty input grants
nothing; stale, malformed, mismatched or non-owner manual events fail closed.
Only the parent CI accounting and final aggregation receive this data, never the
application/build children or uploaded receipts. This is authenticated manual
input under the trusted workflow/runner contract, not a cryptographic signature
or protection against an owner who changes the workflow itself. No real approval
is generated or inferred by the tooling.

Maintained fixture provenance/notices live beside the test data. Include required
safe fixtures with the change. Keep real credentials, account/queue/state data,
outputs, logs and generated caches out of Git and release archives. Test files
and source files have an 800-line ceiling; split by responsibility before growing
near that limit.

## Code and review

Keep command adapters thin, crypto independent of external I/O, and native
platform effects behind the existing adapters. Reuse installed dependencies or
the standard library before adding a new dependency. Use typed errors, input
validation, owner-private file creation, exact exit codes and centralized
redaction. Document every unsafe block's actual native safety contract. Do not
claim portability from cross-compilation alone.

Changes include affected docs/config/fixtures/tests in the same logical unit.
Review real failure paths and final integrated behavior, not only formatted
source. No incomplete migration publication or old-runtime deletion is authorized
as a shortcut to tests. Preserve user data and the working recovery path until
exact-green native evidence, signed compatible artifacts and practical replacement
verification exist.

## Bug reports and security

Report OS/architecture, exact native version/source commit, sanitized command and
error code, and the relevant reviewed log excerpt. Identify whether the failure
comes from the retained launcher or a native binary. Never include passwords,
MFA codes, session tokens, encrypted user stores or link keys.
For sensitive reports use [SECURITY.md](SECURITY.md), not a public issue.
New owner-authored native contributions use GPL-3.0-or-later; preserve third-party
and historical notices under [ATTRIBUTION.md](ATTRIBUTION.md).
