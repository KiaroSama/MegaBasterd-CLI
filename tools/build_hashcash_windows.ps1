param(
    [string] $OutputPath = ""
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Source = Join-Path $Root "src\megabasterd_cli\native\windows\hashcash_solver.c"
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $Root "Bin\hashcash-solver-win64.exe"
}

$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$OutputDir = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$cl = Get-Command cl.exe -ErrorAction SilentlyContinue
if ($cl) {
    & $cl.Source /nologo /O2 /MT /W4 "/Fe:$OutputPath" $Source bcrypt.lib
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Built $OutputPath"
        exit 0
    }
}

$clang = Get-Command clang.exe -ErrorAction SilentlyContinue
if ($clang) {
    & $clang.Source -O3 -Wall -Wextra -o $OutputPath $Source -lbcrypt
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Built $OutputPath"
        exit 0
    }
}

$gcc = Get-Command gcc.exe -ErrorAction SilentlyContinue
if ($gcc) {
    & $gcc.Source -O3 -Wall -Wextra -o $OutputPath $Source -lbcrypt
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Built $OutputPath"
        exit 0
    }
}

throw "No supported Windows C compiler was found. Install Visual Studio Build Tools, LLVM/Clang, or MinGW-w64."
