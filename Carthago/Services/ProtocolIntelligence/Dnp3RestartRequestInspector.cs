// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // Exact standalone DNP3 master-to-outstation unconfirmed user data:
    // one transport/application fragment, cold/warm restart with no objects.
    // CRC establishes framing integrity only, not origin authentication.
    internal static class Dnp3RestartRequestInspector
    {
        internal static bool TryInspect(ReadOnlySpan<byte> frame)
        {
            if (frame.Length != 15 || frame[0] != 5 || frame[1] != 0x64 ||
                frame[2] != 8 || frame[3] != 0xC4 ||
                Dnp3UnsolicitedBinaryEventInspector.Crc(frame[..8]) !=
                    BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(8,2)) ||
                Dnp3UnsolicitedBinaryEventInspector.Crc(frame.Slice(10,3)) !=
                    BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(13,2)))
                return false;
            ushort destination = BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(4,2));
            ushort source = BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(6,2));
            if (source == destination || source >= 0xFFF0 || destination >= 0xFFF0)
                return false;
            return (frame[10] & 0xC0) == 0xC0 &&
                (frame[11] & 0xF0) == 0xC0 && frame[12] is 0x0D or 0x0E;
        }
    }
}
