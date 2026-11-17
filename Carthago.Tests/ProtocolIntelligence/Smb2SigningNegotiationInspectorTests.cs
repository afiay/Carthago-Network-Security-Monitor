// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class Smb2SigningNegotiationInspectorTests
    {
        private static byte[] Frame(ushort security = 1)
        {
            var p = new byte[132];
            p[3] = 128;
            p[4] = 0xfe; p[5] = 0x53; p[6] = 0x4d; p[7] = 0x42;
            W16(p, 8, 64); W32(p, 20, 1); W64(p, 28, 42);
            W16(p, 68, 65); W16(p, 70, security); W16(p, 72, 0x0302);
            return p;
        }
        private static void W16(byte[] p, int at, ushort v) =>
            BinaryPrimitives.WriteUInt16LittleEndian(p.AsSpan(at, 2), v);
        private static void W32(byte[] p, int at, uint v) =>
            BinaryPrimitives.WriteUInt32LittleEndian(p.AsSpan(at, 4), v);
        private static void W64(byte[] p, int at, ulong v) =>
            BinaryPrimitives.WriteUInt64LittleEndian(p.AsSpan(at, 8), v);
        private static bool Inspect(byte[] p, bool complete = true) =>
            Smb2SigningNegotiationInspector.TryInspect(p, 445, 53000, complete, out _);

        [Theory]
        [InlineData((ushort)0, false, false)]
        [InlineData((ushort)1, true, false)]
        [InlineData((ushort)3, true, true)]
        public void CompleteNegotiationReportsOnlyServerFlags(ushort flags, bool enabled, bool required)
        {
            Assert.True(Smb2SigningNegotiationInspector.TryInspect(
                Frame(flags), 445, 53000, true, out var result));
            Assert.Equal(enabled, result.SigningEnabled);
            Assert.Equal(required, result.SigningRequired);
            Assert.Equal((ushort)0x0302, result.Dialect);
        }

        [Fact] public void InvalidSigningFlagsAndUnsupportedDialectFailClosed()
        {
            Assert.False(Inspect(Frame(2)));
            Assert.False(Inspect(Frame(4)));
            var p = Frame(); W16(p, 72, 0x0100); Assert.False(Inspect(p));
        }
        [Fact] public void PartialSpoofedAndClientFramesFailClosed()
        {
            var p = Frame();
            Assert.False(Inspect(p, false));
            Assert.False(Inspect(p.AsSpan(0, 131).ToArray()));
            Assert.False(Smb2SigningNegotiationInspector.TryInspect(p, 53000, 445, true, out _));
            p = Frame(); p[4] = 0; Assert.False(Inspect(p));
            p = Frame(); W32(p, 12, 0xc0000001); Assert.False(Inspect(p));
        }
        [Fact] public void CompoundOrUnboundedSecurityBuffersFailClosed()
        {
            var p = Frame(); W32(p, 24, 128); Assert.False(Inspect(p));
            p = Frame(); W16(p, 124, 128); W16(p, 126, 20); Assert.False(Inspect(p));
            p = Frame(); W16(p, 124, 127); W16(p, 126, 1); Assert.False(Inspect(p));
        }
    }
}
