// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 4271 BGP-4 message envelopes; no real peer ASNs or prefixes.
    public sealed class BgpMessageInspectorTests
    {
        private static byte[] Packet(byte type, int size)
        {
            var bytes = new byte[size];
            for (int i = 0; i < 16; i++) bytes[i] = 0xff;
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(16, 2), (ushort)size);
            bytes[18] = type;
            if (type == 1) bytes[19] = 4;
            return bytes;
        }

        [Fact] public void ValidKeepaliveRecognized()
        {
            Assert.True(BgpMessageInspector.TryInspect(Packet(4, 19), true, out var found));
            Assert.Equal(BgpMessageKind.Keepalive, found.Kind);
        }

        [Fact] public void ValidOpenRecognized()
        {
            Assert.True(BgpMessageInspector.TryInspect(Packet(1, 29), true, out var found));
            Assert.Equal(BgpMessageKind.Open, found.Kind);
        }

        [Fact] public void ValidEmptyUpdateEnvelopeRecognized()
        {
            Assert.True(BgpMessageInspector.TryInspect(Packet(2, 23), true, out var found));
            Assert.Equal(BgpMessageKind.Update, found.Kind);
        }

        [Fact] public void ValidNotificationEnvelopeRecognized()
        {
            Assert.True(BgpMessageInspector.TryInspect(Packet(3, 21), true, out var found));
            Assert.Equal(BgpMessageKind.Notification, found.Kind);
        }

        [Fact] public void ValidRouteRefreshRecognized()
        {
            Assert.True(BgpMessageInspector.TryInspect(Packet(5, 23), true, out var found));
            Assert.Equal(BgpMessageKind.RouteRefresh, found.Kind);
        }

        [Fact] public void UnattestedTcpBoundaryRejected()
        {
            Assert.False(BgpMessageInspector.TryInspect(Packet(4, 19), false, out _));
        }

        [Fact] public void CrossProtocolMarkerRejected()
        {
            var bytes = Packet(4, 19); bytes[3] = 0;
            Assert.False(BgpMessageInspector.TryInspect(bytes, true, out _));
        }

        [Fact] public void TruncatedAndOverlongDeclaredFramesRejected()
        {
            var bytes = Packet(4, 19); bytes[17] = 20;
            Assert.False(BgpMessageInspector.TryInspect(bytes, true, out _));
            bytes[17] = 18;
            Assert.False(BgpMessageInspector.TryInspect(bytes, true, out _));
        }

        [Fact] public void InvalidOpenVersionRejected()
        {
            var bytes = Packet(1, 29); bytes[19] = 3;
            Assert.False(BgpMessageInspector.TryInspect(bytes, true, out _));
        }

        [Fact] public void InvalidHoldTimeRejected()
        {
            var bytes = Packet(1, 29); bytes[23] = 2;
            Assert.False(BgpMessageInspector.TryInspect(bytes, true, out _));
        }

        [Fact] public void ForgedUpdateWithdrawnLengthRejected()
        {
            var bytes = Packet(2, 23); bytes[20] = 9;
            Assert.False(BgpMessageInspector.TryInspect(bytes, true, out _));
        }

        [Fact] public void ForgedPathAttributeLengthRejected()
        {
            var bytes = Packet(2, 23); bytes[22] = 7;
            Assert.False(BgpMessageInspector.TryInspect(bytes, true, out _));
        }

        [Fact] public void KeepaliveCannotHaveTrailingData()
        {
            Assert.False(BgpMessageInspector.TryInspect(Packet(4, 20), true, out _));
        }

        [Fact] public void UnsupportedTypeRejected()
        {
            Assert.False(BgpMessageInspector.TryInspect(Packet(6, 19), true, out _));
        }

        [Fact] public void MaximumSizeBoundaryRejectedWhenWrongType()
        {
            Assert.False(BgpMessageInspector.TryInspect(Packet(4, 4096), true, out _));
            Assert.False(BgpMessageInspector.TryInspect(new byte[4097], true, out _));
        }

        [Fact] public void RepeatedPacketIsNotSessionOrHijackEvidence()
        {
            var bytes = Packet(4, 19);
            Assert.True(BgpMessageInspector.TryInspect(bytes, true, out var first));
            Assert.True(BgpMessageInspector.TryInspect(bytes, true, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public void SensitiveAsnAndPrefixesNeverRetained()
        {
            var bytes = Packet(1, 29); bytes[20] = 0xaa; bytes[21] = 0xbb;
            Assert.True(BgpMessageInspector.TryInspect(bytes, true, out var found));
            Assert.DoesNotContain("43690", found.ToString());
        }
    }
}