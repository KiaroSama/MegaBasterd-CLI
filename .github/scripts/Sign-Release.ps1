# Owner-approved private-trust signing; never claims public CA trust or notarization.
param([Parameter(Mandatory)][ValidateSet('Binaries','Archives')][string]$Stage,
      [Parameter(Mandatory)][string]$Directory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$expected = 'f3347ef7108b0024c794aa6b01da997264846a27bbf8df726c954444d5f89575'
if ([string]::IsNullOrEmpty($env:MBCLI_RELEASE_PFX_BASE64) -or [string]::IsNullOrEmpty($env:MBCLI_RELEASE_PFX_PASSWORD)) {
    throw 'Dedicated owner signing inputs are required for release packaging.'
}
$directoryPath = [IO.Path]::GetFullPath($Directory)
if (-not (Test-Path -LiteralPath $directoryPath -PathType Container)) { throw 'Package directory is missing.' }
$flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
if ($IsWindows) { $flags = $flags -bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet }
$certificate = [Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadPkcs12(
    [Convert]::FromBase64String($env:MBCLI_RELEASE_PFX_BASE64),$env:MBCLI_RELEASE_PFX_PASSWORD,$flags)
$public = $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$actual = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($public)).ToLowerInvariant()
if ($actual -cne $expected -or -not $certificate.HasPrivateKey -or $certificate.NotAfter -le [DateTime]::UtcNow) {
    throw 'Release certificate identity, expiry or private key is invalid.'
}
function Assert-NativeExit { if ($LASTEXITCODE -ne 0) { throw 'Native signing or verification command failed.' } }
function Sign-Detached([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $content = [Security.Cryptography.Pkcs.ContentInfo]::new($bytes)
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new($content,$true)
    $signer = [Security.Cryptography.Pkcs.CmsSigner]::new($certificate)
    $signer.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $signer.DigestAlgorithm = [Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
    $cms.ComputeSignature($signer,$true)
    $encoded = $cms.Encode()
    $verify = [Security.Cryptography.Pkcs.SignedCms]::new($content,$true)
    $verify.Decode($encoded)
    $verify.CheckSignature($true)
    if ($verify.SignerInfos.Count -ne 1 -or $verify.SignerInfos[0].Certificate.Thumbprint -cne $certificate.Thumbprint) {
        throw 'Detached signature signer mismatch.'
    }
    $changed = [byte[]]::new($bytes.Length + 1)
    [Array]::Copy($bytes,$changed,$bytes.Length)
    $changed[$changed.Length-1] = 1
    $tamper = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($changed),$true)
    $tamper.Decode($encoded)
    $rejected = $false
    try { $tamper.CheckSignature($true) } catch [Security.Cryptography.CryptographicException] { $rejected = $true }
    if (-not $rejected) { throw 'Tampered content was not rejected.' }
    [IO.File]::WriteAllBytes($Path+'.p7s',$encoded)
}
$temp = Join-Path $env:RUNNER_TEMP ('mbcli-sign-'+[Guid]::NewGuid().ToString('N'))
$keychain = Join-Path $temp 'owner.keychain-db'
try {
    if ($Stage -eq 'Binaries') {
        [IO.Directory]::CreateDirectory($temp) | Out-Null
        $names = @('mb','mbcli','megabasterd-cli')
        if ($IsWindows) {
            foreach ($name in $names) {
                $path = Join-Path $directoryPath ($name+'.exe')
                $null = Set-AuthenticodeSignature -LiteralPath $path -Certificate $certificate -HashAlgorithm SHA256 -IncludeChain Signer
                & (Join-Path $PSScriptRoot 'Verify-Windows.ps1') -Path $path
            }
            & (Join-Path $PSScriptRoot 'Test-WindowsSignature.ps1') -Path (Join-Path $directoryPath 'mb.exe') -Scratch $temp
        } elseif ($IsMacOS) {
            # A nonempty PUBLIC transport password makes PKCS12 export an encrypted
            # key bag, avoiding Apple's empty-password import ambiguity. It is NOT
            # secret custody: mode-700/600 scratch and deletion protect this file.
            & /bin/chmod 700 $temp; Assert-NativeExit
            $transport = Join-Path $temp 'transport.p12'
            $transportPassword = 'disposable-native-transport'
            $transportBytes = $certificate.ExportPkcs12([Security.Cryptography.X509Certificates.Pkcs12ExportPbeParameters]::Pkcs12TripleDesSha1,$transportPassword)
            [IO.File]::WriteAllBytes($transport,$transportBytes)
            & /bin/chmod 600 $transport; Assert-NativeExit
            & /usr/bin/security create-keychain -p '' $keychain; Assert-NativeExit
            & /usr/bin/security unlock-keychain -p '' $keychain; Assert-NativeExit
            & /usr/bin/security import $transport -k $keychain -P $transportPassword -T /usr/bin/codesign | Out-Null; Assert-NativeExit
            & /usr/bin/security set-key-partition-list -S 'apple-tool:,apple:,codesign:' -s -k '' $keychain | Out-Null; Assert-NativeExit
            $identities = & /usr/bin/security find-identity -p codesigning $keychain
            Assert-NativeExit
            if (($identities -join "`n") -notmatch [regex]::Escape($certificate.Thumbprint)) { throw 'Imported owner key and certificate did not form a native signing identity.' }
            $requirement = '=certificate leaf = H"'+$certificate.Thumbprint+'"'
            foreach ($name in $names) {
                $path = Join-Path $directoryPath $name
                & /usr/bin/codesign --force --sign $certificate.Thumbprint --keychain $keychain --timestamp=none $path; Assert-NativeExit
                & /usr/bin/codesign --verify --strict -R $requirement $path; Assert-NativeExit
            }
            $changed = Join-Path $temp 'tampered'
            $bytes = [IO.File]::ReadAllBytes((Join-Path $directoryPath 'mb'))
            if ($bytes.Length -le 4096) { throw 'Native payload is too small for the integrity regression.' }
            $bytes[4096] = $bytes[4096] -bxor 1
            [IO.File]::WriteAllBytes($changed,$bytes)
            & /usr/bin/codesign --verify --strict -R $requirement $changed 2>$null
            if ($LASTEXITCODE -ne 1) { throw 'Tampered macOS payload was not rejected as invalid.' }
            & /usr/bin/codesign --verify --strict -R $requirement /bin/ls 2>$null
            if ($LASTEXITCODE -ne 3) { throw 'Different macOS signer was not rejected by the owner requirement.' }
        }
        [IO.File]::WriteAllBytes((Join-Path $directoryPath 'OWNER-CERTIFICATE.cer'),$public)
        Copy-Item -LiteralPath (Join-Path (Get-Location) 'docs/SIGNING.md') -Destination (Join-Path $directoryPath 'SIGNING.md')
        $metadata = @{certificate_sha256=$expected; subject=$certificate.Subject; private_trust=$true; public_ca_trusted=$false; apple_notarized=$false; source_commit=(git rev-parse HEAD).Trim()}
        [IO.File]::WriteAllText((Join-Path $directoryPath 'SIGNING.json'),($metadata | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    } else {
        $archives = @(Get-ChildItem -LiteralPath $directoryPath -Filter '*.tar.gz' -File)
        if ($archives.Count -ne 1) { throw 'Expected exactly one release archive.' }
        Sign-Detached $archives[0].FullName
        [IO.File]::WriteAllBytes((Join-Path $directoryPath 'OWNER-CERTIFICATE.cer'),$public)
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Verify-Release.ps1') -Destination (Join-Path $directoryPath 'Verify-Release.ps1')
        & (Join-Path $PSScriptRoot 'Verify-Release.ps1') -Archive $archives[0].FullName -Certificate (Join-Path $directoryPath 'OWNER-CERTIFICATE.cer')
    }
    Write-Output ('Owner signature verified: '+$Stage+'; public certificate SHA256='+$expected+'; private trust only; no notarization.')
} finally {
    if ($IsMacOS -and (Test-Path -LiteralPath $keychain)) { & /usr/bin/security delete-keychain $keychain | Out-Null }
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
    $certificate.Dispose()
}
