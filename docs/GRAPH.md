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

- `tests/` — the separate integration tree, excluded by owner decision. The
  measured effect: 822 nodes, 817 of them net new, taking the graph from 5897
  to 6714. They are neither duplicates nor dead weight — none is isolated, and
  their mean degree (4.29) matches the graph's (4.12) — but every label is a
  full behaviour sentence (`tests_account_documents_malformed_account_roots_…`)
  rather than a symbol, so they read as prose noise over a symbol graph. Only
  68 of their labels overlap the retained graph at all. An earlier draft of this
  note claimed they mirrored the `src/` surface one-for-one and pushed the HTML
  past its 5000-node aggregation threshold; both claims are false, and that
  threshold was already crossed without them at 5408 nodes. The exclusion is
  partial by design: the `*_tests.rs` files that live **inside** `src/` are
  crate unit tests, exercise a real module in place, and still contribute 944
  nodes (16% of the graph, 38% of the 2473 `src/` nodes). Both trees remain
  fully indexed by Codebase-Memory, which is the graph to ask about coverage.
- The current graph is 5897 nodes, 12150 edges and 12 hyperedges: 3260 code,
  1881 document, 611 concept and 145 rationale. Refresh the numbers here from
  `graphify-out/GRAPH_REPORT.md` rather than trusting this paragraph.
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
graphify update .          # code/AST tier only: no model, no tokens
graphify query "what does the vault depend on"
graphify path src/cli/args.rs src/storage/vault.rs --undirected
```

`graphify update` does not read Markdown. It scans code files, and when the
change set holds no code it prints "No tracked code files in change set -
skipping rebuild" and points doc changes at the host-side `/graphify --update`
pipeline instead. So the `.ai/`, `plans/` and `specs/` concept and rationale
nodes, and the `rationale_for` / `implements` edges between them, are refreshed
only by that pipeline run, never by the sync hook. Editing a note under `.ai/`
leaves the semantic tier stale until someone runs it.

Pass `--undirected` to `graphify path` and remember it in `graphify explain`.
`path` forces a directed search by default and ignores the graph's own
`directed` flag, which is `false` here, so a code-to-doc query returns "No
directed path found" even though a real route exists. With `--undirected` the
same pair resolves through `references` and `contains` edges.
The graph is also `multigraph: true`, and its effective reading is undirected
(`directed: false`, which `graphify diagnose multigraph --json` confirms as
`effective_directed: false`). Under that reading 2 of the 12150 edges collapse
onto an existing same-endpoint pair; the directed reading collapses none. Two
collapsed pairs in 12150 edges is noise, but it is not zero, and the number
moves as the graph grows, so re-read it from the diagnose output rather than
from this sentence.

`graphify-out/graph.html` opens in a browser. The graph exceeds the 5000-node
display limit, so the HTML is an aggregated community view; node-level detail
needs `--obsidian`.

## Automatic sync

A maintainer may run an optional, local-only editor `PostToolUse` hook that keeps
both graphs fresh. It is not part of the repository. After a tool call that edits a
file, it:

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

One case needs care rather than a retry. `graphify update` refuses to overwrite
`graph.json` when the rebuild has fewer nodes than the file on disk. The first
instinct is to re-run with `--force`, and on this repository that is wrong:
measured on graphify 0.9.109, a refused run reported 5882 nodes against 5897 on
disk, and forcing it wrote the smaller graph and dropped 18 `_origin: semantic`
nodes from `.ai/LESSON.md` permanently. `--force` bypasses `to_json`'s shrink
check wholesale, and that check is the only thing protecting the semantic tier on
an incremental run; `graphify update` does not accept the narrower
`--allow-dedup-shrink` flag that would make it safe (`graphify extract` does).

So the worker logs the refusal to `$env:TEMP\mbcli-graphify-<pid>.log.refused`
and leaves the graph alone. A refusal is sticky in the sense that the same
rebuild keeps being refused while the true count stays below the stored one, but
it is not a freeze: graph.json is untouched, so the graph goes stale rather than
wrong, and the Codebase-Memory refresh in the same worker is a separate call and
still runs. The way back is the host-side `/graphify --update` pipeline, which
re-merges the semantic tier and raises the count again, not a forced rebuild.

Nodes sourced from files graphify never scans are dropped at merge time, not
kept. A lockfile, `deny.toml` or `.graphifyignore` is not in the scan set, so a
concept node pointing at one can never reappear in a rebuild, and it would trip
the refusal above for a node that has no chance of coming back. The merge checks
every semantic node against the scan manifest for exactly this reason.

The hook and its registration stay in the ignored local editor configuration, so
a clone does not inherit it; without it, run `graphify update .` and re-index
Codebase-Memory by hand after edits.
