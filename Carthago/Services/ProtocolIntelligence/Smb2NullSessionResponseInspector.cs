// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Strict complete-frame SMB2 SESSION_SETUP success with server-declared
    /// IS_NULL flag. Wire observation only: not authenticated server identity,
    /// proof of enumeration, or sufficient R333 detector evidence.
    /// </summary>
    public static class Smb2NullSessionResponseInspector
    {
        public static bool TryInspect(ReadOnlySpan<byte> frame, int? sourcePort,
            int? destinationPort, bool completeTcpFrame, out ulong sessionId)
        {
            sessionId = 0;
            if (!completeTcpFrame || sourcePort != 445 ||
                destinationPort is null or <= 0 or 445 ||
                frame.Length < 76 || frame.Length > 65540 || frame[0] != 0)
                return false;
            int frameSize = (frame[1] << 16) | (frame[2] << 8) | frame[3];
            if (frameSize != frame.Length - 4) return false;
            var h = frame.Slice(4);
            if (h[0] != 0xfe || h[1] != 0x53 || h[2] != 0x4d || h[3] != 0x42 ||
                U16(h, 4) != 64 || U32(h, 8) != 0 ||
                U16(h, 12) != 1 || (U32(h, 16) & 0x20000007u) != 1 ||
                U32(h, 20) != 0 || U64(h, 24) == 0)
                return false;
            ulong id = U64(h, 40);
            if (id == 0 || U16(h, 64) != 9) return false;
            ushort flags = U16(h, 66);
            // Exactly IS_NULL, without guest or reserved bits.
            if (flags != 2) return false;
            int offset = U16(h, 68), length = U16(h, 70);
            if (length == 0)
            {
                if (h.Length != 72 || offset != 0) return false;
            }
            else if (offset < 72 || offset != 72 || (long)offset + length != h.Length)
                return false;
            sessionId = id;
            return true;
        }

        private static ushort U16(ReadOnlySpan<byte> data, int at) =>
            BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(at, 2));
        private static uint U32(ReadOnlySpan<byte> data, int at) =>
            BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(at, 4));
        private static ulong U64(ReadOnlySpan<byte> data, int at) =>
            BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(at, 8));
    }
}
