param(
    [Parameter(Mandatory = $true)]
    [int] $Easiness,

    [Parameter(Mandatory = $true)]
    [string] $TokenHex,

    [int] $Workers = [Environment]::ProcessorCount,

    [int] $TimeoutMs = 300000
)

$ErrorActionPreference = "Stop"

$source = @"
using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading;

public static class MegaHashcashSolver
{
    private const int TokenBytes = 48;
    private const int Repeat = 262144;

    public static string Solve(int easiness, string tokenHex, int workers, int timeoutMs)
    {
        byte[] token = HexToBytes(tokenHex);
        if (token.Length != TokenBytes)
        {
            throw new ArgumentException("Hashcash token must be 48 bytes.");
        }

        workers = Math.Max(1, Math.Min(workers <= 0 ? Environment.ProcessorCount : workers, 32));
        uint threshold = Threshold(easiness);
        long deadline = Stopwatch.GetTimestamp() + (long)(timeoutMs / 1000.0 * Stopwatch.Frequency);

        int stop = 0;
        string result = null;
        Thread[] threads = new Thread[workers];

        for (int worker = 0; worker < workers; worker++)
        {
            int start = worker;
            int step = workers;
            threads[worker] = new Thread(() =>
            {
                byte[] buffer = BuildBuffer(token);
                using (SHA256 sha = SHA256.Create())
                {
                    ulong candidate = (uint)start;
                    while (Volatile.Read(ref stop) == 0 && Stopwatch.GetTimestamp() < deadline)
                    {
                        uint value = (uint)candidate;
                        buffer[0] = (byte)(value >> 24);
                        buffer[1] = (byte)(value >> 16);
                        buffer[2] = (byte)(value >> 8);
                        buffer[3] = (byte)value;

                        byte[] digest = sha.ComputeHash(buffer);
                        uint head =
                            ((uint)digest[0] << 24) |
                            ((uint)digest[1] << 16) |
                            ((uint)digest[2] << 8) |
                            digest[3];

                        if (head <= threshold)
                        {
                            if (Interlocked.CompareExchange(ref stop, 1, 0) == 0)
                            {
                                result = ToHex(buffer, 4);
                            }
                            return;
                        }
                        candidate += (uint)step;
                    }
                }
            });
            threads[worker].IsBackground = true;
            threads[worker].Start();
        }

        foreach (Thread thread in threads)
        {
            int remaining = Math.Max(1, timeoutMs);
            thread.Join(remaining);
        }

        Volatile.Write(ref stop, 1);
        return result;
    }

    private static byte[] BuildBuffer(byte[] token)
    {
        byte[] buffer = new byte[4 + token.Length * Repeat];
        int offset = 4;
        for (int i = 0; i < Repeat; i++)
        {
            Buffer.BlockCopy(token, 0, buffer, offset, token.Length);
            offset += token.Length;
        }
        return buffer;
    }

    private static uint Threshold(int easiness)
    {
        ulong value = (ulong)((((easiness & 0x3F) << 1) + 1)) << (((easiness >> 6) * 7) + 3);
        return (uint)Math.Min(value, UInt32.MaxValue);
    }

    private static byte[] HexToBytes(string hex)
    {
        if (hex == null || (hex.Length % 2) != 0)
        {
            throw new ArgumentException("Hex input has an invalid length.");
        }
        byte[] data = new byte[hex.Length / 2];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return data;
    }

    private static string ToHex(byte[] data, int count)
    {
        char[] chars = new char[count * 2];
        const string alphabet = "0123456789abcdef";
        for (int i = 0; i < count; i++)
        {
            byte value = data[i];
            chars[i * 2] = alphabet[value >> 4];
            chars[i * 2 + 1] = alphabet[value & 0x0F];
        }
        return new string(chars);
    }
}
"@

Add-Type -TypeDefinition $source -Language CSharp

$nonce = [MegaHashcashSolver]::Solve($Easiness, $TokenHex, $Workers, $TimeoutMs)
if ([string]::IsNullOrWhiteSpace($nonce)) {
    exit 2
}

Write-Output $nonce
exit 0
