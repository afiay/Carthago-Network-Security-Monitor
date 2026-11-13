// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // FINS/TCP node-address negotiation, exact command 0 / command 1.
    // Narrow Ethernet node address range, zero means automatic request.
    internal static class FinsNodeNegotiationInspector
    {
        internal readonly record struct Pending(uint RequestedNode, DateTime At);
        private static uint U32(ReadOnlySpan<byte> p, int offset)
            => BinaryPrimitives.ReadUInt32BigEndian(p.Slice(offset,4));
        private static bool Header(ReadOnlySpan<byte> p, int length, uint command)
            => p.Length == length && p[..4].SequenceEqual("FINS"u8) &&
                U32(p,4) == (uint)(length-8) && U32(p,8) == command && U32(p,12) == 0;

        internal static bool TryRequest(ReadOnlySpan<byte> p, DateTime utc, out Pending pending)
        {
            pending = default;
            if (utc.Kind != DateTimeKind.Utc || !Header(p,20,0) || U32(p,16) > 254)
                return false;
            pending = new Pending(U32(p,16),utc);
            return true;
        }

        internal static bool IsMatchingResponse(ReadOnlySpan<byte> p, Pending pending, DateTime utc)
        {
            if (utc.Kind != DateTimeKind.Utc || utc < pending.At ||
                utc - pending.At > TimeSpan.FromSeconds(30) || !Header(p,24,1))
                return false;
            uint client = U32(p,16), server = U32(p,20);
            return client is >= 1 and <= 254 && server is >= 1 and <= 254 &&
                client != server && (pending.RequestedNode == 0 || client == pending.RequestedNode);
        }
    }
}
