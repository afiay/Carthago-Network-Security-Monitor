// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // One Modbus TCP FC20 Read File Record subrequest, reference type 6,
    // 100–120 registers. Only transaction, unit, quantity and time retained.
    // Response bytes never leave the span.
    internal static class ModbusBulkFileReadInspector
    {
        internal readonly record struct Pending(ushort Transaction, byte Unit, ushort Quantity, DateTime At);
        private static ushort U16(ReadOnlySpan<byte> p, int offset)
            => BinaryPrimitives.ReadUInt16BigEndian(p.Slice(offset, 2));
        private static bool Header(ReadOnlySpan<byte> p, int length)
            => p.Length == length && U16(p,2) == 0 &&
                U16(p,4) == length - 6 && p[6] is >= 1 and <= 247;

        internal static bool TryRequest(ReadOnlySpan<byte> p, DateTime utc, out Pending pending)
        {
            pending = default;
            if (utc.Kind != DateTimeKind.Utc || !Header(p,16) ||
                p[7] != 0x14 || p[8] != 7 || p[9] != 6 ||
                U16(p,10) == 0) return false;
            ushort record = U16(p,12), quantity = U16(p,14);
            if (quantity is < 100 or > 120 || record > 9999 ||
                record + quantity > 10000) return false;
            pending = new Pending(U16(p,0),p[6],quantity,utc);
            return true;
        }

        internal static bool IsMatchingResponse(ReadOnlySpan<byte> p, Pending pending, DateTime utc)
        {
            if (utc.Kind != DateTimeKind.Utc || utc < pending.At ||
                utc - pending.At > TimeSpan.FromSeconds(30) ||
                pending.Quantity is < 100 or > 120) return false;
            int bytes = 2 * pending.Quantity;
            return Header(p,11 + bytes) && U16(p,0) == pending.Transaction &&
                p[6] == pending.Unit && p[7] == 0x14 &&
                p[8] == bytes + 2 && p[9] == bytes + 1 && p[10] == 6;
        }
    }
}
