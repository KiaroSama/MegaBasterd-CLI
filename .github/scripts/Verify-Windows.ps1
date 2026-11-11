param([Parameter(Mandatory)][string]$Path)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'Windows owner signature verification requires Windows.' }
# No trust-store writes, network retrieval or payload execution.
if (-not ('Mbcli.WinTrust' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Mbcli {
    public static class WinTrust {
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
        private struct FileInfo {
            public uint Size;
            [MarshalAs(UnmanagedType.LPWStr)] public string Path;
            public IntPtr File;
            public IntPtr Subject;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct TrustData {
            public uint Size;
            public IntPtr Policy;
            public IntPtr Sip;
            public uint Ui;
            public uint Revocation;
            public uint Choice;
            public IntPtr File;
            public uint StateAction;
            public IntPtr State;
            public IntPtr Url;
            public uint Flags;
            public uint Context;
            public IntPtr Settings;
        }
        [DllImport("wintrust.dll", ExactSpelling=true)]
        private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);
        public static uint Check(string path) {
            var file = new FileInfo { Size=(uint)Marshal.SizeOf<FileInfo>(), Path=path };
            var memory = Marshal.AllocHGlobal(Marshal.SizeOf<FileInfo>());
            Marshal.StructureToPtr(file, memory, false);
            var data = new TrustData {
                Size=(uint)Marshal.SizeOf<TrustData>(), Ui=2, Choice=1,
                File=memory, StateAction=1,
                // Cache-only, no revocation lookup for the self-signed pinned
                // certificate, reject MD2/MD4. Never install trust.
                Flags=0x3010
            };
            var action = new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
            try { return unchecked((uint)WinVerifyTrust(new IntPtr(-1), ref action, ref data)); }
            finally {
                data.StateAction=2;
                WinVerifyTrust(new IntPtr(-1), ref action, ref data);
                Marshal.DestroyStructure<FileInfo>(memory);
                Marshal.FreeHGlobal(memory);
            }
        }
    }
}
'@
}
$resolved = [IO.Path]::GetFullPath($Path)
$result = [Mbcli.WinTrust]::Check($resolved)
# Only success or the exact untrusted-root result is eligible. Never accept
# NotTrusted/UnknownError categories wholesale or parse localized error messages.
if ($result -ne 0 -and $result -ne 2148204809) { throw 'Windows owner signature verification failed.' }
# PowerShell prefers a Windows catalog signature on copied OS files. Read the
# embedded PE signer directly so the identity matches the native file check.
try {
    $embedded = [Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($resolved)
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($embedded)
} catch { throw 'Windows owner signature verification failed.' }
try {
    $expected = 'f3347ef7108b0024c794aa6b01da997264846a27bbf8df726c954444d5f89575'
    $actual = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($certificate.RawData)).ToLowerInvariant()
    $now = [DateTime]::UtcNow
    if ($actual -cne $expected -or $now -lt $certificate.NotBefore.ToUniversalTime() -or $now -gt $certificate.NotAfter.ToUniversalTime()) { throw 'Windows owner signature verification failed.' }
    Write-Output ('Windows pinned owner signature verified; OS trust result=0x'+$result.ToString('X8')+'; no trust installed.')
} finally { $certificate.Dispose(); $embedded.Dispose() }
