# Repository Graphs

Two graph indexes make this repository navigable by tooling. Neither is a build
artifact and neither is uploaded anywhere: both are written under ignored
directories and stay on this machine.

| Graph | Tool | Stored in | Use it for |
| --- | --- | --- | --- |
| Symbol graph | Codebase-Memory MCP | `G:\Codebase-Memory-Service\cache` (outside the repo) | call/use/mention edges, architecture, blast radius |
| Concept graph | graphify | `graphify-out/` | communities, god nodes, surprising cross-links, prose notes |

## Codebase-Memory

Registered in the Claude Desktop config as `Codebase-Memory-mcp`, served by a
local daemon on loopback port 9749. Query it through its MCP tools, not the
files.

The index is not persisted to the repository, so a fresh clone has none until it
is built once. Drive it through the service launcher, never the bare binary: the
launcher pins `CBM_CACHE_DIR` to the cache the daemon serves, while the binary on
its own resolves an empty cache and silently builds a graph nothing else will see.

```powershell
& "G:\Codebase-Memory-Service\cbm.ps1" cli index_repository --repo-path "G:\Program Files\Portable\Scripts\MegaBasterd-CLI" --mode full
```

`--mode fast` skips semantic edges; `--mode full` is the default and the one this
repository is indexed with. The first build of this repository takes minutes; a
refresh after a small edit settles in a second or two. The daemon watches only
the project of the active MCP session, so an index built for another project is
refreshed on demand rather than automatically.

## graphify

Built and kept current by the `graphify` CLI. `graphify-out/` is ignored; the
ignore rules that shape the graph live in `.graphifyignore` and are the reason the
graph is small enough to be useful.

Excluded on purpose, each for a different reason:

- `tests/` — the integration suite. Its files mirror the `src/` surface
  one-for-one, so with them the graph held 6256 nodes and 13790 edges and 727 of
  those nodes (12%) re-used `src/` names under a `test_*` spelling. Dropping them
  gives 5408 nodes and 11541 edges, and `vault` resolves once instead of twice.
  This exclusion is partial by design: the 125 `*_tests.rs` files that live
  **inside** `src/` are crate unit tests, exercise a real module in place, and
  still contribute 944 nodes (17%). Only the separate integration tree is out.
  Both trees remain fully indexed by Codebase-Memory, which is the graph to ask
  about coverage.
- `User/`, `Logs/`, `Output/` — runtime state written by a real run, not source.
- `target/`, `.ci-work/`, `.ci-cache/`, `dist/`, `node_modules/` — build output
  and caches.
- `.agents/`, `.codex/`, `.cursor/`, `.cline/`, `.kiro/`, `.claude/` — other
  agents' local state.
- `.ai/PRIVATE/`, `.ai/ARCHIVE/`, `.ai/.cross-project-sync/` — private notes,
  superseded history, and staged imports from other projects.

Retained although git ignores them, because they are the reasoning trail this
project wants searchable: `.ai/` notes, `plans/`, `specs/`, `.specify/`.

The Python reference port is not a `.graphifyignore` concern: it does not exist
in this working tree. CI sparse-checkouts it from a pinned baseline commit into
`.ci-work/baseline/`, which `target/`-style rules already exclude.

Build or refresh:

```powershell
graphify update .          # structural: AST plus Markdown, no model, no tokens
graphify query "what does the vault depend on"
graphify path src/cli/args.rs src/storage/vault.rs
```

`graphify-out/graph.html` opens in a browser. The graph exceeds the 5000-node
display limit, so the HTML is an aggregated community view; node-level detail
needs `--obsidian`.

## Automatic sync

`.claude/hooks/sync-graphs.ps1` is a Claude Code `PostToolUse` hook registered in
`.claude/settings.json`. After a tool call that edits a file, it:

1. reads the event from stdin and takes the edited path,
2. exits silently unless that path is inside this repository and has a modelled
   extension (`.rs`, `.toml`, `.md`, `.yml`, `.yaml`, `.ps1`, `.psm1`, `.json`,
   `.py`) and is not under a generated or runtime root,
3. otherwise spawns one detached worker that runs `graphify update` and then asks
   Codebase-Memory to re-index.

The worker never blocks the edit. Concurrency is delegated to the tools rather
than reinvented here: `graphify update` takes a per-repository lock and queues a
request if a rebuild is already running, so a burst of edits cannot pile up or
lose the last one; the Codebase-Memory call probes the running job first and
starts an index only when none is queued or in flight.

To turn it off, remove the `sync-graphs` entry from `.claude/settings.json`. The
hook is tracked so a clone inherits it; everything else under `.claude/` stays
local.
