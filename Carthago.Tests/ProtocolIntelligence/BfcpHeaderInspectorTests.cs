// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 8855 COMMON-HEADER fixtures; no real session or identity.
    public sealed class BfcpHeaderInspectorTests
    {
        private static byte[] Packet(byte version = 1, byte primitive = 11,
            int payloadWords = 0, bool response = false, bool fragment = false,
            int offsetWords = 0, int fragmentWords = 0)
        {
            int observedWords = fragment ? fragmentWords : payloadWords;
            var bytes = new byte[12 + (fragment ? 4 : 0) + observedWords * 4];
            bytes[0] = (byte)((version << 5) |
                (response ? 0x10 : 0) | (fragment ? 0x08 : 0));
            bytes[1] = primitive;
            bytes[2] = (byte)(payloadWords >> 8);
            bytes[3] = (byte)payloadWords;
            bytes[4] = 0x12; bytes[5] = 0x34; // private conference identifier
            bytes[8] = 0x11; bytes[9] = 0x22; // private transaction identifier
            bytes[10] = 0x33; bytes[11] = 0x44; // private user identifier
            if (fragment)
            {
                bytes[12] = (byte)(offsetWords >> 8);
                bytes[13] = (byte)offsetWords;
                bytes[14] = (byte)(fragmentWords >> 8);
                bytes[15] = (byte)fragmentWords;
            }
            return bytes;
        }

        private static bool Inspect(byte[] packet, out BfcpHeaderObservation observation,
            BfcpTransportKind transport = BfcpTransportKind.ReliableTcp,
            bool complete = true, bool session = true, bool plaintext = true)
            => BfcpHeaderInspector.TryInspect(packet, transport, complete,
                session, plaintext, out observation);

        [Fact] public void ReliableHelloHeaderIsRecognized()
        {
            Assert.True(Inspect(Packet(), out var found));
            Assert.Equal((byte)1, found.Version);
            Assert.Equal((byte)11, found.Primitive);
            Assert.False(found.IsResponseUnverified);
            Assert.Equal(0, found.DeclaredPayloadBytes);
        }

        [Fact] public void UnreliableHelloResponseHeaderIsRecognized()
        {
            Assert.True(Inspect(Packet(version: 2, primitive: 12, response: true),
                out var found, BfcpTransportKind.UnreliableUdp));
            Assert.True(found.IsResponseUnverified);
            Assert.False(found.IsFragment);
        }

        [Fact] public void FloorRequestPayloadIsOnlyShapeNotAuthorization()
        {
            var packet = Packet(primitive: 1, payloadWords: 1);
            packet[12] = 0x04; packet[13] = 0x04; // FLOOR-ID TLV shape
            Assert.True(Inspect(packet, out var found));
            Assert.Equal((byte)1, found.Primitive);
            Assert.Equal(4, found.ObservedPayloadBytes);
        }

        [Fact] public void BoundedUnreliableFragmentIsRecognizedButNotReassembled()
        {
            var fragment = Packet(version: 2, primitive: 11, payloadWords: 4,
                fragment: true, offsetWords: 1, fragmentWords: 2);
            Assert.True(Inspect(fragment, out var found, BfcpTransportKind.UnreliableUdp));
            Assert.True(found.IsFragment);
            Assert.Equal(16, found.DeclaredPayloadBytes);
            Assert.Equal(8, found.ObservedPayloadBytes);
        }

        [Fact] public void TcpAndUdpVersionsCannotBeInterchanged()
        {
            Assert.False(Inspect(Packet(version: 2), out _));
            Assert.False(Inspect(Packet(), out _, BfcpTransportKind.UnreliableUdp));
            Assert.False(Inspect(Packet(), out _, (BfcpTransportKind)99));
        }

        [Fact] public void UnsupportedPrimitivesAndVersionOneExtensionsFail()
        {
            Assert.False(Inspect(Packet(primitive: 0), out _));
            Assert.False(Inspect(Packet(primitive: 18), out _));
            Assert.False(Inspect(Packet(primitive: 17), out _));
            Assert.True(Inspect(Packet(version: 2, primitive: 17),
                out _, BfcpTransportKind.UnreliableUdp));
        }

        [Fact] public void CrossProtocolHeadersAreNotPromoted()
        {
            Assert.False(Inspect(System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1"), out _));
            Assert.False(Inspect(new byte[] { 0x16, 3, 3, 0, 5, 1, 0, 0, 0, 0, 0, 0 }, out _));
        }

        [Fact] public void AllTrustedProducerPrerequisitesAreMandatory()
        {
            var packet = Packet();
            Assert.False(Inspect(packet, out _, complete: false));
            Assert.False(Inspect(packet, out _, session: false));
            Assert.False(Inspect(packet, out _, plaintext: false));
        }

        [Fact] public void TruncatedCommonHeaderFails()
            => Assert.False(Inspect(Packet().Take(11).ToArray(), out _));

        [Fact] public void TruncatedAndOverlongDeclaredPayloadsFail()
        {
            var packet = Packet(payloadWords: 2);
            Assert.False(Inspect(packet.Take(19).ToArray(), out _));
            Assert.False(Inspect(packet.Concat(new byte[4]).ToArray(), out _));
        }

        [Fact] public void MaximumBoundIsEnforcedWithoutAllocation()
        {
            Assert.False(Inspect(new byte[4097], out _));
            var packet = Packet(payloadWords: 1021);
            Assert.True(Inspect(packet, out _));
            Assert.False(Inspect(Packet(payloadWords: 1022), out _));
        }

        [Fact] public void ReservedBitsAndTcpFragmentFlagsFailClosed()
        {
            var reserved = Packet(); reserved[0] |= 1;
            Assert.False(Inspect(reserved, out _));
            var response = Packet(response: true);
            Assert.False(Inspect(response, out _));
            var fragment = Packet(fragment: true, payloadWords: 1, fragmentWords: 1);
            Assert.False(Inspect(fragment, out _));
        }

        [Fact] public void FragmentLengthAndOffsetMustFitDeclaredWhole()
        {
            Assert.False(Inspect(Packet(version: 2, payloadWords: 2,
                fragment: true, offsetWords: 2, fragmentWords: 1),
                out _, BfcpTransportKind.UnreliableUdp));
            Assert.False(Inspect(Packet(version: 2, payloadWords: 2,
                fragment: true, fragmentWords: 0),
                out _, BfcpTransportKind.UnreliableUdp));
            var packet = Packet(version: 2, payloadWords: 2, fragment: true,
                fragmentWords: 1);
            Assert.False(Inspect(packet.Take(15).ToArray(), out _,
                BfcpTransportKind.UnreliableUdp));
        }

        [Fact] public void FragmentRetransmissionAndReorderingAreStateless()
        {
            var first = Packet(version: 2, payloadWords: 3, fragment: true,
                offsetWords: 0, fragmentWords: 1);
            var last = Packet(version: 2, payloadWords: 3, fragment: true,
                offsetWords: 1, fragmentWords: 2);
            Assert.True(Inspect(last, out var a, BfcpTransportKind.UnreliableUdp));
            Assert.True(Inspect(first, out var b, BfcpTransportKind.UnreliableUdp));
            Assert.True(Inspect(last, out var c, BfcpTransportKind.UnreliableUdp));
            Assert.Equal(a, c);
            Assert.True(a.IsFragment);
            Assert.True(b.IsFragment);
        }

        [Fact] public async Task ConcurrentCallsAreDeterministic()
        {
            var packet = Packet(version: 2, primitive: 11);
            var observations = await Task.WhenAll(Enumerable.Range(0, 24)
                .Select(_ => Task.Run(() =>
                {
                    Assert.True(Inspect(packet, out var found,
                        BfcpTransportKind.UnreliableUdp));
                    return found;
                })));
            Assert.All(observations, found => Assert.Equal(observations[0], found));
        }

        [Fact] public void ConferenceTransactionUserAndPayloadNeverLeaveInspector()
        {
            var a = Packet(primitive: 11, payloadWords: 1);
            var b = Packet(primitive: 11, payloadWords: 1);
            b[4] = 0xee; b[8] = 0xff; b[10] = 0xaa;
            a[12] = 0x33; b[12] = 0x99;
            Assert.True(Inspect(a, out var left));
            Assert.True(Inspect(b, out var right));
            Assert.Equal(left, right);
        }

        [Fact] public void RejectedInputAlwaysReturnsDefaultObservation()
        {
            Assert.False(Inspect(Packet(primitive: 0), out var found));
            Assert.Equal(default(BfcpHeaderObservation), found);
        }
    }
}
