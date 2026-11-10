param(
    [Parameter(Mandatory)][string]$ProjectRoot,
    [string]$TestName = 'selection_preserves_explicit_skip_default_and_invalid_retry_contract'
)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($ProjectRoot)
$work = Join-Path $root '.ci-work/selection'
[IO.Directory]::CreateDirectory($work) | Out-Null
$run = [guid]::NewGuid().ToString('N')
$binary = Join-Path $work ('selection-' + $run + '.exe')
$started = [DateTime]::UtcNow
$log = Join-Path $work ('check-selection_' + $started.ToString('yyyy-MM-dd_HH-mm-ss') + '_UTC_' + $run + '.log')
$encoding = [Text.UTF8Encoding]::new($false, $true)
$code = 1
function Write-CheckLog([string]$level, [string]$message) {
    $line = '[' + [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC] [' + $level + '] [CHECK] ' + $message + [Environment]::NewLine
    [IO.File]::AppendAllText($log, $line, $encoding)
}
try {
    Write-CheckLog 'INFO' 'Compiling one dependency-free selection seam.'
    & rustc --edition=2024 --test (Join-Path $root 'tests/selection_contract.rs') -o $binary
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        & $binary --test-threads=1 --exact $TestName
        $code = $LASTEXITCODE
    }
} catch {
    Write-CheckLog 'ERROR' 'Check infrastructure failed.'
    [Console]::Error.WriteLine($_.Exception.Message)
} finally {
    foreach ($owned in @($binary, [IO.Path]::ChangeExtension($binary, '.pdb'))) {
        if ([IO.File]::Exists($owned)) { [IO.File]::Delete($owned) }
    }
    $level = if ($code -eq 0) { 'INFO' } else { 'ERROR' }
    Write-CheckLog $level ('Completed exit_code=' + $code + ' cleanup=complete')
}
exit $code
