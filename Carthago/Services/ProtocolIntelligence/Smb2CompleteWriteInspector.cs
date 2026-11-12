// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // Strict subset: one complete direct-hosted SMB2 WRITE, synchronous and
    // non-compound, no RDMA channel or write-channel-info. Never retain file data,
    // identifiers or names; validate structure only, not server acceptance.
    internal static class Smb2CompleteWriteInspector
    {
        internal static bool TryInspect(ReadOnlySpan<byte> p, int? sourcePort, int? destinationPort,
            out uint writeLength)
        {
            writeLength = 0;
            if (destinationPort != 445 || sourcePort is null or <= 0 or 445
                || p.Length is < 117 or > 4096 || p[0] != 0) return false;
            int frameLength = (p[1] << 16) | (p[2] << 8) | p[3];
            if (frameLength != p.Length - 4 || p[4] != 0xfe || p[5] != 0x53
                || p[6] != 0x4d || p[7] != 0x42) return false;
            var h = p.Slice(4);
            // The SMB2 header starts with the four-byte FE 'SMB' signature.
            // StructureSize is at header offset 4 (wire offset 8), not 0.
            if (U16(h,4) != 64 || U16(h,12) != 9 || U16(h,64) != 49) return false;
            uint flags = U32(h,16);
            // Reject response, async, related-operation, replay and compound framing.
            if ((flags & 0x20000007u) != 0 || U32(h,20) != 0
                || U32(h,36) == 0 || U64(h,40) == 0) return false;
            // A standalone WRITE must carry an actual nonzero file handle.
            ulong persistent = U64(h,80), volatileId = U64(h,88);
            if ((persistent == 0 && volatileId == 0)
                || (persistent == ulong.MaxValue && volatileId == ulong.MaxValue)) return false;
            if (U32(h,96) != 0 || U16(h,104) != 0 || U16(h,106) != 0) return false;
            int offset = U16(h,66);
            uint len = U32(h,68);
            if (offset < 112 || len == 0 || (long)offset + len != h.Length) return false;
            writeLength = len;
            return true;
        }
        private static ushort U16(ReadOnlySpan<byte> s, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(s.Slice(offset,2));
        private static uint U32(ReadOnlySpan<byte> s, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(offset,4));
        private static ulong U64(ReadOnlySpan<byte> s, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(s.Slice(offset,8));
    }
}
