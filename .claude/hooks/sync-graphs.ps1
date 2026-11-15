# Keep both navigation graphs current after a file-changing tool call.
#
# Claude Code PostToolUse hook. It runs in two modes:
#
#   dispatcher (default)  reads the hook event from stdin, decides whether the
#                         edited path is something either graph actually models,
#                         and if so spawns ONE detached worker and returns. This
#                         is the only mode on the caller's critical path, so it
#                         does no I/O beyond parsing and one Start-Process.
#   worker (-Worker)      does the actual refresh: `graphify update`, then a
#                         Codebase-Memory re-index. Runs hidden, off the path.
#
# Concurrency is delegated rather than reinvented:
#   - graphify update takes a per-repo flock and QUEUES a request when a rebuild
#     is already in flight (#1059), so a burst of edits cannot pile up corrupt
#     work or lose the last one; the lock holder drains the queue.
#   - Codebase-Memory is driven with --async, and its own job state is probed
#     first, so a second request joins the running index instead of competing.
#
# Neither refresh is allowed to fail an edit: every step is wrapped, and the
# script always exits 0. A graph that could not be refreshed stays as it was.

[CmdletBinding()]
param(
    # Worker mode marker, set only by the dispatcher's own spawn.
    [switch] $Worker,
    # Edited path, forwarded to the worker. Empty in dispatcher mode when the
    # path is taken from the stdin event instead (the normal case).
    [string] $FilePath = '',
    # Manual-test override: read the path from -FilePath instead of stdin.
    [switch] $NoStdin
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# ---------------------------------------------------------------- filters ----

# Paths in neither graph: generated build output, runtime state, and the local
# agent-config trees that .graphifyignore also drops. Everything else listed
# here IS modelled and must trigger a rebuild: plans/, specs/, .specify/ and
# .ai/ (structural Markdown for graphify). Note the one asymmetry: secrets.md is
# git-ignored AND excluded by .graphifyignore, so it never lands in either graph,
# yet it still passes this filter and costs one rebuild per edit. Harmless, and
# kept here deliberately so that dropping the exclusion later does not silently
# stop the hook from noticing the change.
$SkipRoots = '^(target|\.ci-work|\.git|graphify-out|\.codebase-memory|node_modules|User|Output|Logs|\.claude|\.codex|\.agents|\.kiro|\.cursor|\.cline)(/|$)'

# Only these extensions are structural. Logs, lockfiles, archives, binaries and
# plain text notes are not.
$ModelledExt = @('.rs', '.toml', '.md', '.yml', '.yaml', '.ps1', '.psm1', '.json', '.py')

function Test-ModelledPath {
    param([string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $full = try { [IO.Path]::GetFullPath($Path) } catch { return $false }
    $prefix = [IO.Path]::GetFullPath($RepoRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    $rel = $full.Substring($prefix.Length).Replace('\', '/')
    if ([regex]::IsMatch($rel, $SkipRoots, 'IgnoreCase')) { return $false }
    $ext = [IO.Path]::GetExtension($rel).ToLowerInvariant()
    return ($ModelledExt -ccontains $ext)
}

# ----------------------------------------------------------------- worker ----

function Start-GraphRefresh {
    param([string] $Path)

    # graphify: incremental, local, no model, no tokens. Blocking here is fine;
    # this function only ever runs inside the detached worker. Scope limit worth
    # knowing: `update` is the code/AST tier only. It skips a change set with no
    # code files, so a .ai/ or plans/ edit refreshes Codebase-Memory below but
    # leaves the graphify concept/rationale tier stale until a host-side
    # /graphify --update pipeline run. See docs/GRAPH.md.
    $graphify = Get-Command graphify -ErrorAction SilentlyContinue
    if ($null -ne $graphify) {
        $log = Join-Path $env:TEMP "mbcli-graphify-$PID.log"
        try {
            # Out-File -Encoding utf8, not *>: the native redirect writes UTF-16
            # on Windows PowerShell, which no other tool reads as text.
            & $graphify.Source update $RepoRoot 2>&1 | Out-File -FilePath $log -Encoding utf8

            # A rebuild with FEWER nodes than graph.json is refused, and that
            # refusal is the guard doing its job: do NOT retry with --force.
            # Measured on this repo (graphify 0.9.109): a refused run was
            # 5882 nodes against 5897 on disk, and forcing it wrote the smaller
            # graph and dropped 18 `_origin: semantic` nodes from .ai/LESSON.md
            # for good. The count check is exactly what protects the semantic
            # tier here, so overriding it is the data-loss path, not the fix.
            # A refusal leaves graph.json untouched, so the graph goes stale
            # rather than wrong; the host-side /graphify --update pipeline is
            # what re-merges the tier and clears it. Log the refusal so a
            # permanently-stale graph is visible instead of silent.
            $text = Get-Content -LiteralPath $log -Raw -ErrorAction SilentlyContinue
            if ($text -and $text -match 'Refusing to overwrite') {
                Add-Content -LiteralPath "$log.refused" -Encoding utf8 -Value (
                    "{0}`t{1}" -f (Get-Date -Format 's'), $Path
                )
            }
        } catch {
            Add-Content -LiteralPath "$log.err" -Value $_.ToString() -ErrorAction SilentlyContinue
        }
    }

    # Codebase-Memory: ask the running job first; only start an index when none
    # is queued or in flight. Same shared cache the MCP server uses, reached
    # through the service launcher that pins CBM_CACHE_DIR.
    $launcher = 'G:\Codebase-Memory-Service\cbm.ps1'
    if (Test-Path -LiteralPath $launcher -PathType Leaf) {
        $ps = Join-Path $PSHOME 'powershell.exe'
        if (-not (Test-Path -LiteralPath $ps)) { $ps = 'powershell.exe' }
        try {
            $probe = & $ps -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $launcher `
                cli --quiet index_repository --repo-path $RepoRoot --status true 2>$null
            $busy = ($probe -join "`n") -match '(?im)"?state"?\s*[:=]\s*"?(queued|running)'
            if (-not $busy) {
                & $ps -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $launcher `
                    cli --quiet index_repository --repo-path $RepoRoot --async true 2>$null | Out-Null
            }
        } catch {
            # Service stopped or unreachable: a stale index is not an edit failure.
        }
    }

    # One line of evidence per refresh, so a silent no-op is distinguishable from
    # a hook that never fired. Keyed by the edited path that provoked it.
    try {
        $stamp = Join-Path $env:TEMP 'mbcli-sync-graphs.log'
        Add-Content -LiteralPath $stamp -Value ("{0}`t{1}" -f (Get-Date -Format 's'), $Path) -ErrorAction Stop
    } catch { }
}

if ($Worker) {
    try { Start-GraphRefresh -Path $FilePath } catch { }
    exit 0
}

# ------------------------------------------------------------- dispatcher ----

$path = $FilePath
if (-not $NoStdin) {
    # Claude Code delivers the event as JSON on stdin. Only read it when stdin is
    # actually redirected; otherwise ReadToEnd would block on a console.
    try {
        if ([Console]::IsInputRedirected) {
            $raw = [Console]::In.ReadToEnd()
            if ($null -ne $raw) { $raw = $raw.TrimStart([char]0xFEFF) }
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                # Neither $event nor $input: both are PowerShell automatic variables.
                $hookEvent = $raw | ConvertFrom-Json
                $toolInput = $hookEvent.tool_input
                if ($null -ne $toolInput) {
                    # Edit/Write/NotebookEdit use file_path; MultiEdit carries a
                    # list of edits, each with its own path.
                    if ($toolInput.file_path) { $path = [string] $toolInput.file_path }
                    elseif ($toolInput.edits) {
                        foreach ($edit in @($toolInput.edits)) {
                            if ($edit.file_path) { $path = [string] $edit.file_path; break }
                        }
                    }
                }
            }
        }
    } catch { $path = '' }
}

if (-not (Test-ModelledPath -Path $path)) { exit 0 }

try {
    $ps = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $ps)) { $ps = 'powershell.exe' }
    $argLine = ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Worker -FilePath "{1}"' `
        -f $PSCommandPath, $path.Replace('"', ''))
    Start-Process -FilePath $ps -ArgumentList $argLine -WindowStyle Hidden | Out-Null
} catch {
    # Could not spawn the refresh; the edit itself is unaffected.
}

exit 0
