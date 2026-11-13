// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // Narrow FINS/UDP local-network CPU Data Memory word write. A zero
    // block is a requested value, not proof of changed controller memory.
    internal static class FinsDataMemoryClearInspector
    {
        internal static bool TryInspect(ReadOnlySpan<byte> p)
        {
            // Ten-byte FINS header, two-byte command, six-byte area/address/count,
            // then exactly sixteen 16-bit words. No payload is retained.
            if (p.Length != 50 || p[0] != 0x80 || p[1] != 0 ||
                p[2] != 2 || p[3] != 0 || p[5] != 0 ||
                p[6] != 0 || p[8] != 0 ||
                p[4] is < 1 or > 254 || p[7] is < 1 or > 254 || p[4] == p[7] ||
                p[10] != 1 || p[11] != 2 || p[12] != 0x82 || p[15] != 0 ||
                BinaryPrimitives.ReadUInt16BigEndian(p.Slice(13,2)) > 32752 ||
                BinaryPrimitives.ReadUInt16BigEndian(p.Slice(16,2)) != 16)
                return false;
            foreach (byte value in p[18..])
                if (value != 0) return false;
            return true;
        }
    }
}
