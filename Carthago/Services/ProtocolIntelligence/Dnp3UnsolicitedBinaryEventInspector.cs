// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // Narrow standalone DNP3 UDP frame: unconfirmed outstation user data,
    // one transport/application fragment and indexed group 2 variation 1
    // binary-input events. CRC is integrity, not origin authentication.
    internal static class Dnp3UnsolicitedBinaryEventInspector
    {
        internal static bool TryInspect(ReadOnlySpan<byte> frame)
        {
            if (frame.Length < 10 || frame[0] != 5 || frame[1] != 0x64 ||
                frame[2] < 5 || frame[3] != 0x44 ||
                !ValidCrc(frame[..8], frame.Slice(8, 2))) return false;
            ushort destination = BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(4, 2));
            ushort source = BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(6, 2));
            if (source == destination || source >= 0xFFF0 || destination >= 0xFFF0) return false;
            int length = frame[2] - 5;
            if (length < 11 || frame.Length != 10 + length + 2 * ((length + 15) / 16))
                return false;
            Span<byte> data = stackalloc byte[250];
            int wire = 10, offset = 0;
            while (offset < length)
            {
                int n = Math.Min(16, length - offset);
                var block = frame.Slice(wire, n);
                if (!ValidCrc(block, frame.Slice(wire + n, 2))) return false;
                block.CopyTo(data.Slice(offset, n));
                offset += n;
                wire += n + 2;
            }
            // Transport FIR+FIN, application FIR+FIN+CON+UNS, unsolicited
            // response 0x82, then two IIN bytes (not interpreted).
            if ((data[0] & 0xC0) != 0xC0 || (data[1] & 0xF0) != 0xF0 ||
                data[2] != 0x82 || data[5] != 2 || data[6] != 1 || data[7] != 0x17)
                return false;
            int count = data[8];
            if (count is < 1 or > 32 || length != 9 + count * 2) return false;
            // 1-byte index prefix and one flags byte per binary input event.
            // A repeated index is permitted: several events for one point
            // can occur before delivery. No point index or value is retained.
            return true;
        }

        internal static ushort Crc(ReadOnlySpan<byte> bytes)
        {
            ushort crc = 0;
            foreach (byte item in bytes)
            {
                crc ^= item;
                for (int bit = 0; bit < 8; bit++)
                    crc = (ushort)((crc >> 1) ^ ((crc & 1) == 0 ? 0 : 0xA6BC));
            }
            return (ushort)~crc;
        }

        private static bool ValidCrc(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> wire)
            => Crc(bytes) == BinaryPrimitives.ReadUInt16LittleEndian(wire);
    }
}
