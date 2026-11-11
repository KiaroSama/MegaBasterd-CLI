# Verify detached archive integrity without installing certificates or executing payloads.
param([Parameter(Mandatory)][string]$Archive,[Parameter(Mandatory)][string]$Certificate)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$expected='f3347ef7108b0024c794aa6b01da997264846a27bbf8df726c954444d5f89575'
$certBytes=[IO.File]::ReadAllBytes([IO.Path]::GetFullPath($Certificate))
$actual=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($certBytes)).ToLowerInvariant()
if($actual -cne $expected){throw 'Owner certificate fingerprint mismatch.'}
$cert=[Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
try {
    $path=[IO.Path]::GetFullPath($Archive)
    $bytes=[IO.File]::ReadAllBytes($path)
    $cms=[Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($bytes),$true)
    $cms.Decode([IO.File]::ReadAllBytes($path+'.p7s'))
    $cms.CheckSignature($true)
    if($cms.SignerInfos.Count -ne 1 -or $cms.SignerInfos[0].Certificate.Thumbprint -cne $cert.Thumbprint){throw 'Archive signer mismatch.'}
    if([DateTime]::UtcNow -lt $cert.NotBefore.ToUniversalTime() -or [DateTime]::UtcNow -gt $cert.NotAfter.ToUniversalTime()){throw 'Owner certificate is outside its validity period.'}
    $checksum=([IO.File]::ReadAllText($path+'.sha256',[Text.Encoding]::UTF8).Trim() -split '\s+')[0]
    if($checksum -cne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()){throw 'Archive SHA256 mismatch.'}
    Write-Output 'Archive signature, pinned owner certificate and SHA256 verified. Private trust only; no public CA or Apple notarization claim.'
} finally {$cert.Dispose()}
