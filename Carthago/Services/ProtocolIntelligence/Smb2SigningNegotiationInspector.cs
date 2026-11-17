// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Strict SMB2 NEGOTIATE response observation. A server advertising no
    /// signing requirement is not proof that a session was unsigned or that
    /// the host is sensitive. Do not promote this observation to R339 alone.
    /// </summary>
    public static class Smb2SigningNegotiationInspector
    {
        public readonly record struct Observation(ushort Dialect, bool SigningEnabled, bool SigningRequired);

        public static bool TryInspect(ReadOnlySpan<byte> frame, int? sourcePort,
            int? destinationPort, bool completeTcpFrame, out Observation observation)
        {
            observation = default;
            if (!completeTcpFrame || sourcePort != 445 ||
                destinationPort is null or <= 0 or 445 ||
                frame.Length < 132 || frame.Length > 65540 || frame[0] != 0)
                return false;
            int size = (frame[1] << 16) | (frame[2] << 8) | frame[3];
            if (size != frame.Length - 4) return false;
            var h = frame.Slice(4);
            if (h[0] != 0xfe || h[1] != 0x53 || h[2] != 0x4d || h[3] != 0x42 ||
                U16(h, 4) != 64 || U32(h, 8) != 0 ||
                U16(h, 12) != 0 || (U32(h, 16) & 0x20000007u) != 1 ||
                U32(h, 20) != 0 || U64(h, 24) == 0 ||
                U16(h, 64) != 65)
                return false;
            ushort security = U16(h, 66);
            ushort dialect = U16(h, 68);
            if ((security & ~3) != 0 || (security & 2) != 0 && (security & 1) == 0 ||
                dialect is not (0x0202 or 0x0210 or 0x0300 or 0x0302 or 0x0311))
                return false;
            ushort contexts = U16(h, 70);
            uint contextOffset = U32(h, 124);
            if (dialect != 0x0311 && (contexts != 0 || contextOffset != 0))
                return false;
            // Security buffer is optional; if present it must start at the
            // end of the fixed 64-byte negotiate response and be complete.
            int blobOffset = U16(h, 120), blobLength = U16(h, 122);
            if (blobLength == 0)
            {
                if (blobOffset != 0 || h.Length != 128 || contexts != 0) return false;
            }
            else if (blobOffset != 128 || (long)blobOffset + blobLength > h.Length)
                return false;
            if (dialect == 0x0311 && contexts != 0)
            {
                if (contextOffset < 128 || contextOffset >= h.Length ||
                    (contextOffset & 7) != 0 ||
                    contextOffset < (uint)(blobOffset + blobLength))
                    return false;
            }
            else if (h.Length != 128 + blobLength)
                return false;
            observation = new Observation(dialect, (security & 1) != 0, (security & 2) != 0);
            return true;
        }

        private static ushort U16(ReadOnlySpan<byte> data, int offset) =>
            BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset, 2));
        private static uint U32(ReadOnlySpan<byte> data, int offset) =>
            BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));
        private static ulong U64(ReadOnlySpan<byte> data, int offset) =>
            BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(offset, 8));
    }
}
