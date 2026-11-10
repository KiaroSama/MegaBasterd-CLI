# Attribution and licensing

MegaBasterd CLI - Copyright (c) 2026 Kiaro Sama.

- Original author: Kiaro Sama
- Author: https://github.com/KiaroSama
- Repository: https://github.com/KiaroSama/MegaBasterd-CLI

## Native version

The new Rust implementation and project-owned native build tooling are licensed
under **GPL-3.0-or-later**: you may redistribute and modify them under version 3
of the GNU General Public License, or, at your option, any later version.
The full license text is in [LICENSE](LICENSE).

This software is provided without warranty, including the implied warranties of
merchantability or fitness for a particular purpose. See the license for details.

The native implementation is a modified replacement of the earlier Python CLI.
When distributing binaries, provide the matching Corresponding Source, including
the build scripts, lockfile, project license and applicable dependency notices.
A source tree for another commit is not the matching source for a binary.

## Historical versions

Earlier versions were distributed under the MIT License. Those existing grants
are not revoked by this change. Their notice is preserved in
[licenses/MIT-historical.txt](licenses/MIT-historical.txt); preserve it when
redistributing that code or substantial portions of it. During the migration,
the retained Python implementation continues to carry that historical grant.

## References and dependencies

The CLI is inspired by [MegaBasterd](https://github.com/tonikelope/megabasterd),
by tonikelope, whose code has its own GPL version 3 terms. MEGA wire behavior is
also studied against the [official MEGA SDK](https://github.com/meganz/sdk),
whose code carries its own BSD notices. Reference documentation and behavioral
compatibility do not relicense third-party code. This project is not affiliated
with MEGA or the original MegaBasterd project.

Third-party Rust dependencies retain their respective licenses and copyright
notices. Cargo.lock identifies the versions; the distribution's third-party
notice bundle must identify the actually included dependencies and reproduce
applicable license/notice files. The project's GPL grant does not override those
licenses. Do not remove original notices when adapting or redistributing code.

## Unicode data

The pinned Unicode 14 full case-fold mapping in the native folder-filter engine
is generated from the retained Python 3.11.9 Unicode database. Unicode data is
copyright Unicode, Inc.; the applicable permission notice is preserved in
[licenses/Unicode-3.0.txt](licenses/Unicode-3.0.txt). Regeneration tooling and the
independent wildcard oracle record the exact Unicode/runtime versions.

## Test fixtures

The small maintained PNG/MP4/WebM regression fixtures in `tests/fixtures/media/`
come from web-platform-tests contributors under BSD-3-Clause. Their exact source
commit, hashes and complete notice are retained beside the files. The test-only
TLS certificates/key in `tests/fixtures/proxy_tls/` come from rustls under MIT;
their notice and provenance are retained there. They are public synthetic test
material, never production credentials, trusted roots, or signing inputs.
