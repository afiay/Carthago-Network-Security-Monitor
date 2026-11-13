// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // Exact standalone Modbus TCP function 06 request, never a port guess.
    // The value and transaction identifier are not retained.
    internal static class ModbusSingleRegisterWriteInspector
    {
        internal static bool TryInspect(ReadOnlySpan<byte> payload, out uint point)
        {
            point = 0;
            if (payload.Length != 12 ||
                BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2)) != 0 ||
                BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2)) != 6 ||
                payload[6] is < 1 or > 247 || payload[7] != 6)
                return false;
            point = ((uint)payload[6] << 16) |
                BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(8, 2));
            return true;
        }
    }
}
