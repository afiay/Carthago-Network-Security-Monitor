// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // Exact BACnet/IP Original-Unicast, local NPDU, unsegmented confirmed
    // ReinitializeDevice (20) coldstart/warmstart without optional password.
    // A request is not a device acknowledgment or physical restart.
    internal static class BacnetReinitializeDeviceInspector
    {
        internal static bool TryInspect(ReadOnlySpan<byte> p)
        {
            if (p.Length != 12 || p[0] != 0x81 || p[1] != 0x0A ||
                BinaryPrimitives.ReadUInt16BigEndian(p.Slice(2,2)) != p.Length ||
                p[4] != 1 || (p[5] & 0xFC) != 0x04 ||
                (p[6] & 0xFD) != 0 || (p[7] & 0x0F) > 5 ||
                (p[7] >> 4) > 7 || p[9] != 20 ||
                p[10] != 0x09 || p[11] is not (0 or 1))
                return false;
            return true;
        }
    }
}
