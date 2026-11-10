# Maintained codec fixtures

Unmodified binary test media from [web-platform-tests/wpt](https://github.com/web-platform-tests/wpt)
at commit `705331d44391a7656f0e4ab6b312a34ca3ead219` (retrieved 2026-10-15).
The source directory is [media/](https://github.com/web-platform-tests/wpt/tree/705331d44391a7656f0e4ab6b312a34ca3ead219/media).
Copyright web-platform-tests contributors; BSD-3-Clause. The complete upstream
notice is retained in [LICENSE-BSD-3-Clause.txt](LICENSE-BSD-3-Clause.txt).

| File | Bytes | SHA-256 | Expected content |
| --- | ---: | --- | --- |
| `1x1-green.png` | 135 | `a236213916dd30bd771a233aa1d66381eabf335bf8885304b75a4e2e370d68ce` | 1x1 green image |
| `2x2-green.mp4` | 3503 | `f2923f95cb1653b6bb1b63a91b50940809d94708d68a2f2065bcad320aed0ff5` | 2x2 green video |
| `2x2-green.webm` | 814 | `aff421ce65673c73ebee67c1e4a7bd45843a490d4715717c3ed6760d88776634` | 2x2 green video |

These are encoded binary media, not UTF-8 text. Do not decode/rewrite them as
text. Native tests verify the pinned hashes before real decoding. These small
maintained files cover actual PNG/MP4/WebM decoding and the encrypted thumbnail
attachment path; they do not establish large-media performance, exact seeking,
GPU support, or interoperability with every codec/container.

The production image decoder and process adapter are used unchanged. MP4/WebM
checks require a real `ffmpeg` with seekable `fd` input from its inherited
regular-file stdin, matching `ffprobe`, H.264/VP8 decode, and MJPEG encode. CI supplies
and verifies the pair. Set `MEGABASTERD_FFMPEG` to the chosen executable path;
missing/incompatible tooling fails the native media tests, never silently skips.
No media tool is installed by the application. File-only tests use no network;
attribute tests connect only to their owned loopback TLS fixture.

The test implementation and native execution remain separate evidence: fixture
provenance/hash verification alone is not a passing Rust test or GPU result.
