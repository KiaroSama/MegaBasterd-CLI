# Synthetic source-oracle transfer fixtures

These are public test-only data, not user files, account keys or signing material.
The vectors were generated from the retained Python baseline at commit
`c4559ecef08c1fb47cc57669230d2f6013520416`, using Python 3.11.9 and
PyCryptodome 3.23.0. Exact source SHA256 values are recorded in `vectors.json`
and checked before loading either source module.

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

## Regeneration

`tools/oracle/transfer_fixture.py` is offline tooling only, never the Rust
application's runtime or a Python bridge. Run it with the pinned existing
Python interpreter and `-I`, supplying these arguments:

- `--source-root`: a source checkout matching the recorded source hashes.
- `--provenance`: the existing `tests/fixtures/crypto-vectors.json`.
- `--output`: a new empty fixture directory.
- `--check`: compare an existing fixture directory byte-for-byte without overwriting.

Generation never overwrites an existing file: identical bytes are accepted,
and differing bytes fail. The check requires every file to exist and reuses the same
source algorithm to validate every ciphertext plus the UTF-8 JSON document.
It creates a unique UTF-8 UTC diagnostic log in `Logs/oracle/`, never imports
the CLI, accesses accounts or performs network requests. Run under the owning
project's bounded runner; no package installation is needed. After old-source
retirement, use a read-only historical checkout with the same hashes.

## Execution evidence and limits

The source-only generation returned child exit 0. Its first guarded run
reported and terminated a surviving descendant; a later non-overwriting
verification completed cleanly (exit 0, no surviving child). Both receipts are
kept privately. No Rust compilation, native test or CI success is inferred
from fixture generation or formatting.

Own generator and fixtures: GPL-3.0-or-later; historical source rights remain
as recorded in `ATTRIBUTION.md` and `licenses/MIT-historical.txt`.
