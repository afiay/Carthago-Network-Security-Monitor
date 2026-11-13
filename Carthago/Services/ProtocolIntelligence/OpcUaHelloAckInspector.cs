// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // OPC UA TCP HEL / ACK (Part 6). Narrow plaintext version-zero subset.
    // Only buffer sizes are kept; endpoint URL bytes never leave the span.
    internal static class OpcUaHelloAckInspector
    {
        internal readonly record struct Hello(uint Receive, uint Send, DateTime At);
        private static uint U32(ReadOnlySpan<byte> p, int offset)
            => BinaryPrimitives.ReadUInt32LittleEndian(p.Slice(offset, 4));
        private static bool Header(ReadOnlySpan<byte> p, byte a, byte b, byte c)
            => p.Length >= 8 && p[0] == a && p[1] == b && p[2] == c &&
                p[3] == (byte)'F' && U32(p,4) == (uint)p.Length;
        private static bool Buffer(uint value) => value is >= 8192 and <= 16777216;
        private static bool Limits(ReadOnlySpan<byte> p)
            => U32(p,8) == 0 && Buffer(U32(p,12)) && Buffer(U32(p,16)) &&
                (U32(p,20) == 0 || U32(p,20) >= 8192);
        internal static bool TryHello(ReadOnlySpan<byte> p, DateTime utc, out Hello hello)
        {
            hello = default;
            if (utc.Kind != DateTimeKind.Utc || p.Length is < 43 or > 4096 ||
                !Header(p, (byte)'H', (byte)'E', (byte)'L') || !Limits(p)) return false;
            uint len = U32(p,28);
            if (len != (uint)(p.Length - 32) || len is < 11 or > 2048) return false;
            ReadOnlySpan<byte> url = p.Slice(32);
            if (!url.Slice(0,10).SequenceEqual("opc.tcp://"u8)) return false;
            // Strict printable ASCII, no userinfo, whitespace or query/fragment.
            // This is a bounded shape check, not an authenticated URL or DNS name.
            foreach (byte b in url)
                if (b is < 0x21 or > 0x7E || b is (byte)'@' or (byte)'?' or (byte)'#') return false;
            if (url[10] is (byte)'/' or (byte)':' || url[10] == (byte)'.') return false;
            hello = new Hello(U32(p,12),U32(p,16),utc);
            return true;
        }
        internal static bool IsMatchingAck(ReadOnlySpan<byte> p, Hello hello, DateTime utc)
            => utc.Kind == DateTimeKind.Utc && utc >= hello.At &&
                utc - hello.At <= TimeSpan.FromSeconds(30) &&
                p.Length == 28 && Header(p,(byte)'A',(byte)'C',(byte)'K') && Limits(p) &&
                U32(p,12) <= hello.Send && U32(p,16) <= hello.Receive;
    }
}
