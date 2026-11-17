// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class Smb2NullSessionResponseInspectorTests
    {
        private static byte[] Response()
        {
            var p = new byte[76];
            p[3] = 72;
            p[4] = 0xfe; p[5] = 0x53; p[6] = 0x4d; p[7] = 0x42;
            W16(p, 8, 64); W16(p, 16, 1);
            W32(p, 20, 1); W64(p, 28, 123); W64(p, 44, 456);
            W16(p, 68, 9); W16(p, 70, 2);
            return p;
        }
        private static void W16(byte[] p, int o, ushort v) =>
            BinaryPrimitives.WriteUInt16LittleEndian(p.AsSpan(o, 2), v);
        private static void W32(byte[] p, int o, uint v) =>
            BinaryPrimitives.WriteUInt32LittleEndian(p.AsSpan(o, 4), v);
        private static void W64(byte[] p, int o, ulong v) =>
            BinaryPrimitives.WriteUInt64LittleEndian(p.AsSpan(o, 8), v);
        private static bool Inspect(byte[] p, bool complete = true) =>
            Smb2NullSessionResponseInspector.TryInspect(p, 445, 52000, complete, out _);

        [Fact] public void CompleteNullSessionResponseIsObservedWithoutClaimingEnumeration()
        {
            var p = Response();
            Assert.True(Smb2NullSessionResponseInspector.TryInspect(p, 445, 52000,
                true, out var session));
            Assert.Equal(456UL, session);
        }
        [Fact] public void GuestAndNormalSessionsAreNotNullSessions()
        {
            var p = Response(); W16(p, 70, 1); Assert.False(Inspect(p));
            W16(p, 70, 0); Assert.False(Inspect(p));
            W16(p, 70, 3); Assert.False(Inspect(p));
        }
        [Fact] public void FailedAndUntrustedResponsesAreRejected()
        {
            var p = Response(); W32(p, 12, 0xc000006d); Assert.False(Inspect(p));
            p = Response(); Assert.False(Inspect(p, false));
            Assert.False(Smb2NullSessionResponseInspector.TryInspect(p, 52000, 445, true, out _));
        }
        [Fact] public void CompoundAndTruncatedFramesAreRejected()
        {
            var p = Response(); W32(p, 24, 72); Assert.False(Inspect(p));
            p = Response(); Assert.False(Inspect(p.AsSpan(0, 75).ToArray()));
            p = Response(); p[3] = 71; Assert.False(Inspect(p));
        }
        [Fact] public void UnexpectedSecurityBlobAndZeroSessionIdAreRejected()
        {
            var p = Response(); W64(p, 44, 0); Assert.False(Inspect(p));
            p = Response(); W16(p, 72, 72); W16(p, 74, 1); Assert.False(Inspect(p));
        }
    }
}
