// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // Exact EtherNet/IP encapsulation RegisterSession request and response.
    // The opaque sender context is retained only in bounded pending state.
    internal static class EtherNetIpRegisterSessionInspector
    {
        internal readonly record struct Pending(ulong Context, DateTime At);
        private static ushort U16(ReadOnlySpan<byte> p,int i)
            => BinaryPrimitives.ReadUInt16LittleEndian(p.Slice(i,2));
        private static uint U32(ReadOnlySpan<byte> p,int i)
            => BinaryPrimitives.ReadUInt32LittleEndian(p.Slice(i,4));
        private static ulong Context(ReadOnlySpan<byte> p)
            => BinaryPrimitives.ReadUInt64LittleEndian(p.Slice(12,8));
        private static bool Header(ReadOnlySpan<byte> p)
            => p.Length == 28 && U16(p,0) == 0x0065 && U16(p,2) == 4 &&
                U32(p,8) == 0 && U32(p,20) == 0 &&
                U16(p,24) == 1 && U16(p,26) == 0;
        internal static bool TryRequest(ReadOnlySpan<byte> p, DateTime utc, out Pending pending)
        {
            pending = default;
            if (utc.Kind != DateTimeKind.Utc || !Header(p) || U32(p,4) != 0)
                return false;
            pending = new Pending(Context(p),utc);
            return true;
        }
        internal static bool IsMatchingResponse(ReadOnlySpan<byte> p, Pending pending, DateTime utc)
            => utc.Kind == DateTimeKind.Utc && utc >= pending.At &&
                utc - pending.At <= TimeSpan.FromSeconds(30) && Header(p) &&
                U32(p,4) != 0 && Context(p) == pending.Context;
    }
}
