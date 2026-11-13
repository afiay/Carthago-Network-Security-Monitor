// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // Narrow exact Modbus TCP FC22 Mask Write Register request:
    // AND=0, OR=0 requests a resulting zero register independently of
    // the previous value. No register number, transaction or data retained.
    internal static class ModbusClearMaskWriteInspector
    {
        internal static bool TryInspect(ReadOnlySpan<byte> p)
        {
            return p.Length == 14 &&
                BinaryPrimitives.ReadUInt16BigEndian(p.Slice(2,2)) == 0 &&
                BinaryPrimitives.ReadUInt16BigEndian(p.Slice(4,2)) == 8 &&
                p[6] is >= 1 and <= 247 && p[7] == 0x16 &&
                BinaryPrimitives.ReadUInt16BigEndian(p.Slice(10,2)) == 0 &&
                BinaryPrimitives.ReadUInt16BigEndian(p.Slice(12,2)) == 0;
        }
    }
}
