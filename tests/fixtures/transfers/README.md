# Synthetic source-oracle transfer fixtures

These are public test-only data, not user files, account keys or signing material.
The vectors were generated from the retained Python baseline at commit
`c4559ecef08c1fb47cc57669230d2f6013520416`, using Python 3.11.9 and
PyCryptodome 3.23.0. Exact source SHA256 values are recorded in `vectors.json`
and identify the historical modules used during generation.

The plaintext is defined independently of the Rust implementation:
`byte(i) = (13*i + 7) % 256`. Sizes 0, 17 and 131089 exercise an empty file,
a partial AES block, and the first 128 KiB chunk followed by a 17-byte tail.
The baseline computes ciphertext, packed raw file keys, ordered plaintext
chunk MACs and SHA256 expectations. Binary ciphertext is deliberately not
UTF-8 text. The zero-byte file is an intentional maintained fixture.

`src/transfers/download_peer_tests.rs` uses these ciphertext bytes through a
bounded local TLS peer, actual ranged HTTP downloads, native staging, resume,
on-disk MAC verification and final publication. The upload peer tests compare
recovered plaintext with the independent SHA256 expectations; upload keys are
random, so its wire ciphertext is not expected to equal these fixed-key files.
Synthetic tests do not prove live MEGA/account behavior or real-media codecs.

## Provenance and native verification

The historical generator is preserved at
[`6eb6155:tools/oracle/transfer_fixture.py`](https://github.com/KiaroSama/MegaBasterd-CLI/blob/6eb6155/tools/oracle/transfer_fixture.py).
It has been removed from the current Rust-only source tree. The recorded source
hashes and independent expectations remain frozen; do not regenerate expected
ciphertext from the Rust code under test.

`cargo test --locked --lib transfers::download_peer_tests` and
`cargo test --locked --lib transfers::upload_peer_tests` exercise these vectors
through the native transfer implementation. `cargo xtask verify` runs those
tests as part of the complete suite and records the actual commit/results.
The fixtures require no historical interpreter during normal builds or CI.

Own generator and fixtures: GPL-3.0-or-later; historical source rights remain
as recorded in `ATTRIBUTION.md` and `licenses/MIT-historical.txt`.
