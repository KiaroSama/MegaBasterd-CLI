param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $CliArgs
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
# Native failures retain their own exit code instead of entering the startup catch.
$PSNativeCommandUseErrorActionPreference = $false
if ($null -eq $CliArgs) { $CliArgs = @() }

# Candidate distribution entrypoint; the native binary owns menus and private logs.
# Kept separate from Run.ps1 until the complete migration passes its cutover gates.
$ProjectRoot = $PSScriptRoot
$Binary = Join-Path $ProjectRoot "mb.exe"
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    [Console]::Error.WriteLine("[ERROR] Native mb.exe is missing beside the launcher. Extract a verified native release; no dependency was installed.")
    exit 1
}

try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
} catch {
    # Console encoding can be unavailable in redirected or older hosts.
}

$env:MEGABASTERD_PROJECT_ROOT = $ProjectRoot
try {
    & $Binary @CliArgs
    $Code = $LASTEXITCODE
    if ($null -eq $Code) { $Code = 1 }
    exit $Code
} catch {
    # Native/PowerShell exception messages can contain private paths or arguments.
    [Console]::Error.WriteLine("[ERROR] Native CLI could not be started; no secret arguments were printed.")
    exit 1
}
