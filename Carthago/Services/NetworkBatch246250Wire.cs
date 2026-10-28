// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services
{
    // First-segment, bounded, captured-byte operation classification only.
    // Never retain FTP paths, SMB file contents or application credentials.
    internal static class NetworkBatch246250Wire
    {
        internal static bool FtpUpload(ReadOnlySpan<byte> payload, int? sourcePort,
            int? destinationPort, out string operation)
        {
            operation = "";
            if (destinationPort != 21 || sourcePort == 21 || payload.Length is < 8 or > 256
                || payload[^2] != 13 || payload[^1] != 10) return false;
            var stor = Prefix(payload, "STOR ");
            var appe = Prefix(payload, "APPE ");
            if (!stor && !appe) return false;
            var name = payload.Slice(5, payload.Length - 7);
            if (name.Length is < 1 or > 160) return false;
            foreach (var b in name)
                if (b < 33 || b > 126) return false;
            operation = stor ? "ftp.stor" : "ftp.appe";
            return true;
        }

        private static bool Prefix(ReadOnlySpan<byte> data, string expected)
        {
            if (data.Length < expected.Length) return false;
            for (var i = 0; i < expected.Length; i++)
            {
                var b = data[i];
                if (b >= (byte)'a' && b <= (byte)'z') b -= 32;
                if (b != (byte)expected[i]) return false;
            }
            return true;
        }

        internal static bool Smb2Write(ReadOnlySpan<byte> payload, int? sourcePort, int? destinationPort)
        {
            if (destinationPort != 445 || sourcePort == 445 || payload.Length < 117
                || payload[0] != 0) return false;
            var frameLength = payload[1] << 16 | payload[2] << 8 | payload[3];
            if (frameLength is < 113 or > 1_048_576
                || payload[4] != 0xfe || payload[5] != 0x53
                || payload[6] != 0x4d || payload[7] != 0x42
                || BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(8, 2)) != 64
                || BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(16, 2)) != 9
                || (BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(20, 4)) & 1) != 0
                || BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(68, 2)) != 49)
                return false;
            var dataOffset = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(70, 2));
            var dataLength = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(72, 4));
            return dataOffset >= 112 && dataLength > 0 && dataLength <= 1_048_576
                && (long)dataOffset + dataLength <= frameLength;
        }
    }
}
