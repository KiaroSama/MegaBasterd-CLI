# Contributing

The application, tests and build driver use Rust 1.99.1, edition 2024. Install a
native linker/SDK and follow the checked-in lockfile. Run commands from the
repository root.

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo xtask media
cargo xtask verify
cargo build --locked --release --bins -p megabasterd-cli
cargo xtask package
```

`cargo xtask media` obtains a checksum-pinned FFmpeg/ffprobe 9.0.2 pair for real
MP4/WebM decoding tests. On Unix it builds a minimal test-only toolchain; on
Windows it extracts the pinned public binary pair. Nothing installs media tools
into the user's application or system. A local compatible FFmpeg pair can also be
supplied through `MEGABASTERD_FFMPEG` when running targeted tests.

`cargo xtask verify` builds every test harness, discovers its tests, executes all
of them, rejects ignored/missing results and checks every applicable parity
mapping. It supplies an isolated `MEGABASTERD_USER_DIR` under `.ci-work/`. No live
MEGA credentials are needed: bounded local TLS peers exercise the real wire paths.
The test profile optimizes cryptographic dependencies so KDF tests remain practical.
For a narrow edit use `cargo test --locked --test NAME`; tests involving discovered
user paths require the same isolated user override.

## CI and test accounting

The CI matrix uses actual native runners for Linux x64, Windows x64 and both
macOS architectures. Pushes to `main`/`develop` and every PR build all Release aliases, run unit,
integration, regression, process, filesystem, cryptographic-vector, network-peer,
media and command-line tests, and package binaries plus source and checksums.
Formatting, Clippy/types, advisories/licenses/sources and LLVM line coverage run
as separate required checks. The coverage threshold remains 76 percent.

The immutable baseline is `c4559ecef08c1fb47cc57669230d2f6013520416`. Its ledger
contains 1,416 static test definitions across 164 modules (117 parameterized
definitions, 118 decorators). These are source contracts, not a claimed count of
runtime-expanded pytest cases. The full ledger remains in
`tests/fixtures/contract_coverage.json`; no baseline case has been removed or
exempted from native assertion accounting. Rust tests may group related cases.
Python-specific import, launcher and old-data-reader tests use explicit Rust
replacements; the row's reason records changed mechanisms and policies.

When changing a mapped assertion, review its invariant and variants before
updating its SHA-256. Never change an identity, delete a failing case, mark it
retired, or point it at an unrelated passing helper. The Rust driver checks
source digests and the exact harness identities against discovery and execution.
Each platform writes `.ci-work/receipt.json` with the tested commit, architecture,
native test count and the disposition of all 1,416 contracts.
The accompanying `source-contracts.xml` reports those same preserved identities
in JUnit format; it is assertion-mapping evidence, not a second test execution. Platform-specific
cases must execute on their applicable native runner; they are not claimed as
passing elsewhere.

## Distribution

`cargo xtask package` uses already-built Release binaries. Artifacts include
all three aliases, SHA256SUMS, project licensing and the matching Cargo source
package. Do not describe unsigned CI artifacts as signed releases. Published
binaries need matching Corresponding Source and applicable dependency notices.
Keep credentials, logs, caches, generated media tools and user data out of Git
and out of release archives.

See [migration notes](docs/MIGRATION.md), [upstream review](docs/UPSTREAM.md),
[architecture](docs/ARCHITECTURE.md), and [security policy](SECURITY.md).
