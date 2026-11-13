// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // Exact unconnected CIP Identity Reset, type zero. The session must
    // come from the capture-qualified RegisterSession response.
    internal static class EtherNetIpIdentityResetInspector
    {
        internal readonly record struct Session(uint Handle, DateTime At);
        private static ushort U16(ReadOnlySpan<byte> p,int i)
            => BinaryPrimitives.ReadUInt16LittleEndian(p.Slice(i,2));
        private static uint U32(ReadOnlySpan<byte> p,int i)
            => BinaryPrimitives.ReadUInt32LittleEndian(p.Slice(i,4));
        internal static bool TryInspect(ReadOnlySpan<byte> p, Session session, DateTime utc)
        {
            if (utc.Kind != DateTimeKind.Utc || utc < session.At ||
                utc - session.At > TimeSpan.FromSeconds(30) || session.Handle == 0 ||
                p.Length != 47 || U16(p,0) != 0x006F || U16(p,2) != 23 ||
                U32(p,4) != session.Handle || U32(p,8) != 0 || U32(p,20) != 0 ||
                U32(p,24) != 0 || U16(p,28) > 30 || U16(p,30) != 2 ||
                U16(p,32) != 0 || U16(p,34) != 0 ||
                U16(p,36) != 0x00B2 || U16(p,38) != 7)
                return false;
            return p[40..].SequenceEqual("\u0005\u0002\u0020\u0001\u0024\u0001\u0000"u8);
        }
    }
}
