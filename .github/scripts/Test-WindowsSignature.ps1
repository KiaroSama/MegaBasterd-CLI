param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Scratch)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'Windows native signature checks require Windows.' }
$signerSource = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Sign-Release.ps1'),[Text.UTF8Encoding]::new($false,$true))
if ($signerSource.Contains('$rootStore.Add(')) { throw 'Signing must not modify the trusted-root store.' }
$verifier = Join-Path $PSScriptRoot 'Verify-Windows.ps1'
& $verifier -Path $Path
function Assert-Rejected([string]$Candidate) {
    $rejected = $false
    try { & $verifier -Path $Candidate } catch {
        if ($_.Exception.Message -cne 'Windows owner signature verification failed.') { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw 'An invalid native owner signature was accepted.' }
}
# Change an actual first-section payload byte, not the checksum or certificate table.
$changed = Join-Path $Scratch 'tampered.exe'
$bytes = [IO.File]::ReadAllBytes($Path)
$pe = [BitConverter]::ToInt32($bytes,0x3c)
$section = $pe + 24 + [BitConverter]::ToUInt16($bytes,$pe+20)
$length = [BitConverter]::ToUInt32($bytes,$section+16)
$offset = [BitConverter]::ToUInt32($bytes,$section+20)
if ($length -eq 0 -or $offset -ge $bytes.Length -or ([uint64]$offset+$length) -gt $bytes.Length) { throw 'PE test section is invalid.' }
$bytes[$offset] = $bytes[$offset] -bxor 1
try {
    [IO.File]::WriteAllBytes($changed,$bytes)
    Assert-Rejected $changed
    # Require an actual different embedded signer, not merely an unsigned file.
    $other = (Get-Process -Id $PID).Path
    $otherCertificate = [Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($other)
    try {
        $otherHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($otherCertificate.GetRawCertData())).ToLowerInvariant()
        if ($otherHash -ceq 'f3347ef7108b0024c794aa6b01da997264846a27bbf8df726c954444d5f89575') { throw 'Wrong-owner fixture unexpectedly has the release identity.' }
        Assert-Rejected $other
    } finally { $otherCertificate.Dispose() }
} finally {
    if (Test-Path -LiteralPath $changed) { Remove-Item -LiteralPath $changed -Force }
}
Write-Output 'Native owner identity and payload-tamper rejection verified without trust installation.'
