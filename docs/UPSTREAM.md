# MegaBasterd upstream review

Reviewed `tonikelope/megabasterd` through its latest commit
[`c4b8b76dcf03e726aac77f8959ab90f920765124`](https://github.com/tonikelope/megabasterd/commit/c4b8b76dcf03e726aac77f8959ab90f920765124)
(version 8.61, 2026-09-24). Java sources are reference material; no Java source or
runtime is included in this repository. This is a behavioral port to the CLI.

| Upstream change | Native Rust disposition |
| --- | --- |
| [`fce7789`](https://github.com/tonikelope/megabasterd/commit/fce778990e02fbcc2599a64c30c8b5e9b9700541), #753: preserve `/` in base64 proxy credentials and avoid ambiguous auth parsing | Implemented in `storage::proxies::import_proxy` and proxy-list import. Host/path parsing follows credential separation; standard URL credentials use the unambiguous URL parser. Malformed ports/auth/control characters are rejected. Regression tests cover a base64 `/` and numeric URL passwords. |
| [`3bb42c7`](https://github.com/tonikelope/megabasterd/commit/3bb42c7f7bdad46fa5ea38b22830f0de74d4362e), #thumbnail-ssl-handshake: endpoint selection and bounded retry | Attribute tickets no longer force `ssl`; encrypted attribute bytes use the returned endpoint. Uploads retry transient network errors/429/5xx at most five times with cancellable backoff. Bad handles and fixed errors remain final; `pfa` registration is not replayed by the retry loop. |
| [`3c01722`](https://github.com/tonikelope/megabasterd/commit/3c01722f5d615d22bcd3e34d6451eab287996fea), #643: limit integrity/post-processing concurrency | Already implemented by the checkpoint's global Rust verification permit, cancellable waits and RAII release. Downloads stream to held files; no Java chunk-join stage is needed. |
| #778/#760/#758: SmartProxy runtime races, exhausted pools and quota deadlocks | The checkpoint uses a shared `Arc<Pool>` with synchronized snapshots, reload outside the pool mutex, bounded cooldown state and cancellable quota waits. Forced-proxy paths refuse direct fallback. Native routing/quota/concurrency tests cover these paths. |
| #784/#783: headless folder acceptance and optional per-file public links | Native folder downloads do not open GUI confirmation dialogs; include/exclude and index selection are CLI options. Upload public links are opt-in through `--share`. Existing native folder/import/share tests cover tree relationships and outcomes. |
| #774: independent post-finish commands | Existing Rust download/upload finalization and queue/batch hooks use explicit literal argument vectors, owned process trees and recorded completion outcomes. |
| #773/#776: memory bounds and thread-pool deadlock | Native workers are bounded by validated settings, chunk buffers are bounded, file I/O is streamed, and worker threads are joined. The Java shared cached-pool/GC mechanisms have no native equivalent to carry over. |
| #792/#787/#789/#786 and localization-only commits | Swing tree expansion, selection labels, clipboard context menus, toolbar buttons and translated desktop strings are specific to the Java GUI. The CLI has no corresponding widgets; importing those commits would not add CLI behavior. |
| `c4b8b76`: bump upstream version to 8.61 | Records the review boundary; the independent CLI version remains 2.0.0. |

The upstream review does not claim parity with MegaBasterd's entire desktop UI.
Native network tests use local controlled peers rather than personal accounts.
