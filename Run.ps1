param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $CliArgs
)

# Thin PowerShell entry point for the native mb binary. Everything here is only
# what PowerShell must do before exec: locate the executable, fix console
# encoding, propagate the exit code. All behaviour lives in Rust.
Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
if ($null -eq $CliArgs) {
    $CliArgs = @()
}
try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
} catch {
    # Older hosts reject the change; the CLI still runs, only its glyphs suffer.
}
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ExeName = if ($IsWindows -or $env:OS -eq "Windows_NT") { "mb.exe" } else { "mb" }
# Prefer a packaged build, then a release build, then a debug build, so the
# launcher works in a checkout and in an extracted release alike. A release
# archive keeps the executable beside this script, so the root is a candidate too.
$Candidates = @(
    (Join-Path $ProjectRoot $ExeName),
    (Join-Path $ProjectRoot (Join-Path "dist" $ExeName)),
    (Join-Path $ProjectRoot (Join-Path "target/release" $ExeName)),
    (Join-Path $ProjectRoot (Join-Path "target/debug" $ExeName))
)
$Binary = $null
foreach ($candidate in $Candidates) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        $Binary = $candidate
        break
    }
}
if ($null -eq $Binary) {
    [Console]::Error.WriteLine(
        "mb was not found. Build it first with: cargo build --release --bin mb")
    exit 127
}
# The user directory stays beside the launcher unless the caller overrides it,
# which matches how the packaged release is meant to be extracted.
if ([string]::IsNullOrWhiteSpace($env:MEGABASTERD_USER_DIR)) {
    $env:MEGABASTERD_USER_DIR = Join-Path $ProjectRoot "User"
}
& $Binary @CliArgs
exit $LASTEXITCODE
