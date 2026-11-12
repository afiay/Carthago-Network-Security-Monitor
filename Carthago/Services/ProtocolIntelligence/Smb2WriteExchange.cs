// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // Standalone synchronous plaintext WRITE exchange. Raw identifiers remain
    // in bounded per-flow state, never in exported records.
    internal static class Smb2WriteExchange
    {
        internal readonly record struct Pending(Guid RequestId, ulong MessageId, ulong SessionId,
            uint TreeId, uint RequestedLength, uint EndSequence, DateTime RequestedUtc);

        internal static Pending FromValidatedRequest(ReadOnlySpan<byte> p, uint length,
            Guid requestId, uint endSequence, DateTime nowUtc)
            => new(requestId, U64(p,28), U64(p,44), U32(p,40), length, endSequence, nowUtc);

        internal static bool TryMatchReply(ReadOnlySpan<byte> p, Pending request, uint ack,
            DateTime nowUtc, out uint status, out uint? count)
        {
            status = 0;
            count = null;
            if (request.RequestId == Guid.Empty || request.RequestedUtc.Kind != DateTimeKind.Utc
                || nowUtc.Kind != DateTimeKind.Utc || nowUtc < request.RequestedUtc
                || nowUtc - request.RequestedUtc > TimeSpan.FromSeconds(30)
                || unchecked((int)(ack - request.EndSequence)) < 0
                || p.Length is < 76 or > 4096 || p[0] != 0) return false;
            int frameLength = (p[1] << 16) | (p[2] << 8) | p[3];
            if (frameLength != p.Length - 4 || p[4] != 0xfe || p[5] != 0x53
                || p[6] != 0x4d || p[7] != 0x42 || U16(p,8) != 64
                || U16(p,16) != 9 || U32(p,24) != 0
                || (U32(p,20) & 0x20000007u) != 1
                || U64(p,28) != request.MessageId || U32(p,40) != request.TreeId
                || U64(p,44) != request.SessionId) return false;
            uint wireStatus = U32(p,12);
            if (wireStatus == 0)
            {
                // WRITE Response StructureSize=17; fixed body is 16 bytes.
                if (p.Length != 84 || U16(p,68) != 17
                    || U16(p,80) != 0 || U16(p,82) != 0) return false;
                uint acknowledged = U32(p,72);
                if (acknowledged == 0 || acknowledged > request.RequestedLength) return false;
                count = acknowledged;
            }
            else
            {
                // Simple final ERROR, without error contexts. No STATUS_PENDING.
                if ((wireStatus & 0xc0000000u) != 0xc0000000u || U16(p,68) != 9
                    || p[70] != 0 || p[71] != 0) return false;
                uint byteCount = U32(p,72);
                if (byteCount == 0)
                {
                    if (p.Length != 77 || p[76] != 0) return false;
                }
                else if (76L + byteCount != p.Length) return false;
            }
            status = wireStatus;
            return true;
        }
        private static ushort U16(ReadOnlySpan<byte> s, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(s.Slice(offset,2));
        private static uint U32(ReadOnlySpan<byte> s, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(offset,4));
        private static ulong U64(ReadOnlySpan<byte> s, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(s.Slice(offset,8));
    }
}
