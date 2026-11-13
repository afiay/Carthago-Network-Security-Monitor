// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // One complete master unconfirmed user-data frame, Disable Unsolicited
    // for all three event classes (group 60 variations 2, 3, 4).
    // CRC is not sender authentication; no reporting outcome is inferred.
    internal static class Dnp3DisableUnsolicitedInspector
    {
        internal static bool TryInspect(ReadOnlySpan<byte> frame)
        {
            if (frame.Length != 24 || frame[0] != 5 || frame[1] != 0x64 ||
                frame[2] != 17 || frame[3] != 0xC4 ||
                Dnp3UnsolicitedBinaryEventInspector.Crc(frame[..8]) !=
                    BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(8,2)) ||
                Dnp3UnsolicitedBinaryEventInspector.Crc(frame.Slice(10,12)) !=
                    BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(22,2)))
                return false;
            ushort destination = BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(4,2));
            ushort source = BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(6,2));
            if (source == destination || source >= 0xFFF0 || destination >= 0xFFF0 ||
                (frame[10] & 0xC0) != 0xC0 || (frame[11] & 0xF0) != 0xC0 ||
                frame[12] != 0x15) return false;
            int seen = 0;
            for (int i = 13; i < 22; i += 3)
            {
                if (frame[i] != 60 || frame[i+2] != 6) return false;
                int bit = frame[i+1] switch { 2 => 1, 3 => 2, 4 => 4, _ => 0 };
                if (bit == 0 || (seen & bit) != 0) return false;
                seen |= bit;
            }
            return seen == 7;
        }
    }
}
