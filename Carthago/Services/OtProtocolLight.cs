// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services
{
    // Bounded, wire-derived OT protocol identification. A port guess or
    // packet Info string never promotes ApplicationProtocol. This is only
    // framing recognition, not operation decoding or authorization evidence.
    internal static class OtProtocolLight
    {
        private static bool Port(int? source, int? destination, int expected)
            => source == expected || destination == expected;

        internal static bool TryIdentifyTcp(ReadOnlySpan<byte> bytes,
            int? sourcePort, int? destinationPort, out string protocol)
        {
            protocol = string.Empty;
            if (Port(sourcePort, destinationPort, 502) && bytes.Length >= 8
                && bytes[2] == 0 && bytes[3] == 0)
            {
                var length = BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(4, 2));
                if (length is >= 2 and <= 254 && bytes.Length >= 6 + length
                    && bytes[7] is >= 1 and <= 127)
                {
                    // Only client-to-server requests can be classified as
                    // write operations. A response from port 502 is not proof
                    // of a new write attempt.
                    protocol = destinationPort == 502 && bytes.Length >= 12
                        && (bytes[7] is 5 or 6 or 15 or 16)
                        ? "modbus.write" : "modbus";
                    return true;
                }
            }

            // DNP3 link-layer header includes an independently checkable CRC.
            if (Port(sourcePort, destinationPort, 20000) && bytes.Length >= 10
                && bytes[0] == 0x05 && bytes[1] == 0x64 && bytes[2] >= 5
                && BinaryPrimitives.ReadUInt16LittleEndian(bytes.Slice(8, 2))
                    == Dnp3HeaderCrc(bytes.Slice(0, 8)))
            {
                protocol = "dnp3";
                return true;
            }

            // ISO-on-TCP TPKT + COTP Data TPDU + S7 protocol identifier.
            if (Port(sourcePort, destinationPort, 102) && bytes.Length >= 17
                && bytes[0] == 0x03 && bytes[1] == 0x00
                && BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(2, 2)) is >= 17
                && BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(2, 2)) <= bytes.Length
                && bytes[4] == 0x02 && bytes[5] == 0xf0 && bytes[6] == 0x80
                && bytes[7] == 0x32 && bytes[8] is 1 or 2 or 3 or 7
                && bytes[9] == 0 && bytes[10] == 0)
            {
                protocol = "s7comm";
                return true;
            }

            return false;
        }

        internal static bool TryIdentifyUdp(ReadOnlySpan<byte> bytes,
            int? sourcePort, int? destinationPort, out string protocol)
        {
            protocol = string.Empty;
            // Mode 7 private request, MON_GETLIST_1 (42). No sync/response promotion.
            if (destinationPort == 123 && sourcePort != 123 && bytes.Length >= 8
                && (bytes[0] & 7) == 7 && ((bytes[0] >> 3) & 7) is 3 or 4
                && (bytes[1] & 0x80) == 0 && bytes[3] == 42)
            { protocol = "ntp.mode7.monlist"; return true; }
            if (!Port(sourcePort, destinationPort, 47808) || bytes.Length < 6
                || bytes[0] != 0x81 || bytes[1] is not (0x0a or 0x0b)
                || BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(2, 2)) != bytes.Length
                || bytes[4] != 0x01) return false;
            protocol = bytes.Length >= 8 && bytes[5] == 0x00 && bytes[6] == 0x10
                ? bytes[7] == 0x08 ? "bacnet.whois" : bytes[7] == 0x00 ? "bacnet.iam" : "bacnet"
                : "bacnet";
            return true;
        }

        private static ushort Dnp3HeaderCrc(ReadOnlySpan<byte> header)
        {
            ushort crc = 0;
            foreach (var b in header)
            {
                crc ^= b;
                for (var bit = 0; bit < 8; bit++)
                    crc = (ushort)((crc & 1) != 0 ? (crc >> 1) ^ 0xa6bc : crc >> 1);
            }
            return (ushort)~crc;
        }
    }
}
