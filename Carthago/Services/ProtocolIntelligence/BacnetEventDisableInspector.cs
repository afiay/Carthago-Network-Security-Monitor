// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // Narrow BACnet WriteProperty Event_Enable request for Analog Input or
    // Binary Input: exact three-bit all-zero EventTransitionBits.
    // No priority, array index, raw object ID or controller outcome retained.
    internal static class BacnetEventDisableInspector
    {
        internal static bool TryInspect(ReadOnlySpan<byte> p)
        {
            if (p.Length != 22 || p[0] != 0x81 || p[1] != 0x0A ||
                BinaryPrimitives.ReadUInt16BigEndian(p.Slice(2,2)) != p.Length ||
                p[4] != 1 || (p[5] & 0xFC) != 0x04 ||
                (p[6] & 0xFD) != 0 || (p[7] & 0x0F) > 5 ||
                (p[7] >> 4) > 7 || p[9] != 15 ||
                p[10] != 0x0C || p[15] != 0x19 || p[16] != 35 ||
                p[17] != 0x3E || p[18] != 0x82 || p[19] != 5 ||
                p[20] != 0 || p[21] != 0x3F)
                return false;
            uint objectId = BinaryPrimitives.ReadUInt32BigEndian(p.Slice(11,4));
            return (objectId >> 22) is 0 or 3 && (objectId & 0x3FFFFF) != 0x3FFFFF;
        }
    }
}
