// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // Modbus TCP function 03 requests exceeding the protocol's 125-register
    // limit and exact exception 03 (Illegal Data Value). Never retains register
    // address or quantity; only the transaction/unit needed for correlation.
    internal static class ModbusOversizedReadExchangeInspector
    {
        internal readonly record struct Pending(ushort Transaction, byte Unit, DateTime At);
        private static ushort U16(ReadOnlySpan<byte> p, int offset)
            => BinaryPrimitives.ReadUInt16BigEndian(p.Slice(offset, 2));
        private static bool Header(ReadOnlySpan<byte> p, int length)
            => p.Length == length && U16(p, 2) == 0 &&
                U16(p, 4) == length - 6 && p[6] is >= 1 and <= 247;

        internal static bool TryRequest(ReadOnlySpan<byte> p, DateTime utc, out Pending pending)
        {
            pending = default;
            if (utc.Kind != DateTimeKind.Utc || !Header(p, 12) ||
                p[7] != 3 || U16(p, 10) <= 125) return false;
            pending = new Pending(U16(p, 0), p[6], utc);
            return true;
        }

        internal static bool IsMatchingException(ReadOnlySpan<byte> p, Pending pending, DateTime utc)
            => utc.Kind == DateTimeKind.Utc && utc >= pending.At &&
                utc - pending.At <= TimeSpan.FromSeconds(30) && Header(p, 9) &&
                U16(p, 0) == pending.Transaction && p[6] == pending.Unit &&
                p[7] == 0x83 && p[8] == 3;
    }
}
