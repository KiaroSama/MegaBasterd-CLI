param([Parameter(Mandatory)][string]$Directory,[Parameter(Mandatory)][string]$SourceCommit)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if(-not $IsWindows){throw 'PE metadata verification requires Windows.'}
if($SourceCommit -notmatch '^[0-9a-f]{40}$'){throw 'Expected source commit is invalid.'}
foreach($name in @('mb','mbcli','megabasterd-cli')){
    $path=Join-Path $Directory ($name+'.exe')
    $version=[Diagnostics.FileVersionInfo]::GetVersionInfo([IO.Path]::GetFullPath($path))
    if($version.CompanyName -cne 'Kiaro Sama' -or $version.ProductName -cne 'MegaBasterd CLI' -or
       $version.FileVersion -cne '2.0.0' -or $version.ProductVersion -cne '2.0.0' -or
       $version.Comments -cne ('Source commit: '+$SourceCommit)){
        throw 'Native release metadata mismatch.'
    }
}
Write-Output 'All native aliases carry the exact owner, product, version and source commit.'
