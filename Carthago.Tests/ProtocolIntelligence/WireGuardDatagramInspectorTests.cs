// SPDX-License-Identifier: MIT
using System;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic public WireGuard wire-layout fixtures; no peer keys or captured secrets.
    public sealed class WireGuardDatagramInspectorTests
    {
        private static byte[] Packet(byte type, int length)
        {
            var bytes = new byte[length];
            bytes[0] = type;
            if (length >= 8)
                bytes[4] = 0x2A; // synthetic index, never retained in observation
            return bytes;
        }

        [Theory]
        [InlineData(1, 148, WireGuardMessageKind.HandshakeInitiation)]
        [InlineData(2, 92, WireGuardMessageKind.HandshakeResponse)]
        [InlineData(3, 64, WireGuardMessageKind.CookieReply)]
        [InlineData(4, 32, WireGuardMessageKind.TransportData)]
        public void KnownMessageShapesAreRecognized(byte type, int length, WireGuardMessageKind expected)
        {
            Assert.True(WireGuardDatagramInspector.TryInspect(Packet(type, length), true, out var found));
            Assert.Equal(expected, found.Kind);
            Assert.Equal(length, found.DatagramLength);
            Assert.True(found.ContainsOpaqueContent);
        }

        [Fact]
        public void UntrustedBoundaryRejected()
        {
            Assert.False(WireGuardDatagramInspector.TryInspect(Packet(1, 148), false, out _));
        }

        [Fact]
        public void ReservedBytesRejected()
        {
            var bytes = Packet(1, 148);
            bytes[2] = 1;
            Assert.False(WireGuardDatagramInspector.TryInspect(bytes, true, out _));
        }

        [Fact]
        public void UnknownTypeRejected()
        {
            Assert.False(WireGuardDatagramInspector.TryInspect(Packet(5, 148), true, out _));
        }

        [Theory]
        [InlineData(1, 147)]
        [InlineData(2, 91)]
        [InlineData(3, 63)]
        public void FixedSizeTruncationRejected(byte type, int length)
        {
            Assert.False(WireGuardDatagramInspector.TryInspect(Packet(type, length), true, out _));
        }

        [Theory]
        [InlineData(1, 149)]
        [InlineData(2, 93)]
        [InlineData(3, 65)]
        public void OverlongFixedSizeRejected(byte type, int length)
        {
            Assert.False(WireGuardDatagramInspector.TryInspect(Packet(type, length), true, out _));
        }

        [Fact]
        public void TransportRequiresAlignedCiphertextAndTag()
        {
            Assert.False(WireGuardDatagramInspector.TryInspect(Packet(4, 31), true, out _));
            Assert.False(WireGuardDatagramInspector.TryInspect(Packet(4, 33), true, out _));
            Assert.True(WireGuardDatagramInspector.TryInspect(Packet(4, 48), true, out _));
        }

        [Fact]
        public void TransportMinFrameIsOpaque()
        {
            Assert.True(WireGuardDatagramInspector.TryInspect(Packet(4, 32), true, out var found));
            Assert.True(found.ContainsOpaqueContent);
        }

        [Fact]
        public void BenignDnsOrIkeCannotMatch()
        {
            Assert.False(WireGuardDatagramInspector.TryInspect(
                new byte[] { 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, true, out _));
            Assert.False(WireGuardDatagramInspector.TryInspect(
                new byte[] { 0x16, 0xFE, 0xFD, 0, 0, 0, 0, 0 }, true, out _));
        }

        [Fact]
        public void OversizeRejected()
        {
            Assert.False(WireGuardDatagramInspector.TryInspect(new byte[65_536], true, out _));
        }

        [Fact]
        public void RepeatDoesNotClaimReplay()
        {
            var bytes = Packet(4, 48);
            Assert.True(WireGuardDatagramInspector.TryInspect(bytes, true, out var first));
            Assert.True(WireGuardDatagramInspector.TryInspect(bytes, true, out var second));
            Assert.Equal(first, second);
        }

        [Fact]
        public void ObservationNeverContainsIndicesCountersOrKeys()
        {
            var bytes = Packet(4, 48);
            bytes[8] = 0xF0;
            Assert.True(WireGuardDatagramInspector.TryInspect(bytes, true, out var found));
            Assert.DoesNotContain("42", found.ToString()); // synthetic receiver index
            Assert.DoesNotContain("240", found.ToString()); // synthetic counter byte
        }
    }
}
