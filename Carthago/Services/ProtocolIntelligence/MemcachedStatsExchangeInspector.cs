// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Strict bounded memcached ASCII STATS exchange evidence. The caller must independently
    /// establish complete ordered TCP reassembly, direction, plaintext and flow identity.
    /// A parsed response is not proof of unauthorized enumeration or server identity.
    /// </summary>
    public static class MemcachedStatsExchangeInspector
    {
        public const int MaxResponseBytes = 16384;
        public const int MaxStatLines = 128;

        public static bool IsCompleteStatsExchange(
            ReadOnlySpan<byte> request, ReadOnlySpan<byte> response,
            bool completeBidirectionalCapture, bool verifiedPlaintext, bool sameTcpExchange,
            out int statCount)
        {
            statCount = 0;
            if (!completeBidirectionalCapture || !verifiedPlaintext || !sameTcpExchange ||
                !request.SequenceEqual("stats\r\n"u8) ||
                response.Length < 5 || response.Length > MaxResponseBytes)
                return false;

            int offset = 0;
            while (offset < response.Length)
            {
                int end = response.Slice(offset).IndexOf("\r\n"u8);
                if (end < 0) return false;
                var line = response.Slice(offset, end);
                offset += end + 2;
                if (line.SequenceEqual("END"u8))
                    return offset == response.Length && statCount > 0;
                if (!line.StartsWith("STAT "u8) || ++statCount > MaxStatLines)
                {
                    statCount = 0;
                    return false;
                }
                var fields = line.Slice(5);
                int space = fields.IndexOf((byte)' ');
                if (space <= 0 || space == fields.Length - 1)
                {
                    statCount = 0;
                    return false;
                }
                for (int i = 0; i < fields.Length; i++)
                {
                    byte c = fields[i];
                    if (c < 0x21 || c > 0x7e)
                    {
                        statCount = 0;
                        return false;
                    }
                }
            }
            statCount = 0;
            return false;
        }
    }
}
