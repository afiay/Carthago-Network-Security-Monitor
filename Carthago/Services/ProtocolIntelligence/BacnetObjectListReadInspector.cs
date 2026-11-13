// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // Exact BACnet/IP local unsegmented ReadProperty: Device Object_List
    // without an array index. Does not establish a returned directory.
    internal static class BacnetObjectListReadInspector
    {
        internal static bool TryInspect(ReadOnlySpan<byte> p)
        {
            if (p.Length != 17 || p[0] != 0x81 || p[1] != 0x0A ||
                BinaryPrimitives.ReadUInt16BigEndian(p.Slice(2,2)) != p.Length ||
                p[4] != 1 || (p[5] & 0xFC) != 0x04 ||
                (p[6] & 0xFD) != 0 || (p[7] & 0x0F) > 5 ||
                (p[7] >> 4) > 7 || p[9] != 12 ||
                p[10] != 0x0C || p[15] != 0x19 || p[16] != 76)
                return false;
            uint objectId = BinaryPrimitives.ReadUInt32BigEndian(p.Slice(11,4));
            return (objectId >> 22) == 8 && (objectId & 0x3FFFFF) != 0x3FFFFF;
        }
    }
}
