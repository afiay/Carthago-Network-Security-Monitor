// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 7296 envelope fixtures; not authenticated VPN sessions.
    public sealed class IkeV2DatagramInspectorTests
    {
        private static byte[] Packet(byte payloadType = 33, ushort payloadLength = 4, bool nat = false)
        {
            int offset = nat ? 4 : 0;
            var bytes = new byte[offset + 28 + payloadLength];
            bytes[offset] = 0xA5; // nonzero initiator SPI
            bytes[offset + 16] = payloadType;
            bytes[offset + 17] = 0x20; // IKEv2
            bytes[offset + 18] = 34; // IKE_SA_INIT
            bytes[offset + 19] = 0x08; // initiator
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 24, 4), (uint)(28 + payloadLength));
            bytes[offset + 28] = payloadType == 46 ? (byte)35 : (byte)0;
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset + 30, 2), payloadLength);
            return bytes;
        }

        [Fact]
        public void ValidIkeSaInitIsRecognizedWithoutAuthenticationClaim()
        {
            Assert.True(IkeV2DatagramInspector.TryInspect(Packet(), 500, 500, true, out var found));
            Assert.Equal((byte)34, found.ExchangeType);
            Assert.False(found.ContainsEncryptedPayload);
            Assert.Equal(1, found.OuterPayloadCount);
        }

        [Fact]
        public void NatTraversalMarkerIsRecognizedAndExcludedFromDeclaredLength()
        {
            Assert.True(IkeV2DatagramInspector.TryInspect(Packet(nat: true), 4500, 4500, true, out var found));
            Assert.True(found.NatTraversalMarkerPresent);
        }

        [Fact]
        public void NatTraversalRejectsNonEspMarkerSpoofing()
        {
            var bytes = Packet(nat: true);
            bytes[0] = 1;
            Assert.False(IkeV2DatagramInspector.TryInspect(bytes, 4500, 4500, true, out _));
        }

        [Fact]
        public void UntrustedDatagramBoundaryIsRejected()
        {
            Assert.False(IkeV2DatagramInspector.TryInspect(Packet(), 500, 500, false, out _));
        }

        [Fact]
        public void UnknownPortDoesNotTurnMetadataIntoIkeDecoder()
        {
            Assert.False(IkeV2DatagramInspector.TryInspect(Packet(), 12345, 12346, true, out _));
        }

        [Fact]
        public void TruncatedIkeHeaderFailsClosed()
        {
            var bytes = Packet();
            Assert.False(IkeV2DatagramInspector.TryInspect(bytes.AsSpan(0, 27), 500, 500, true, out _));
        }

        [Fact]
        public void WrongDeclaredLengthFailsClosed()
        {
            var bytes = Packet();
            bytes[27] = 0x7F;
            Assert.False(IkeV2DatagramInspector.TryInspect(bytes, 500, 500, true, out _));
        }

        [Theory]
        [InlineData(0x10)]
        [InlineData(0x30)]
        public void UnsupportedIkeMajorVersionFailsClosed(byte version)
        {
            var bytes = Packet();
            bytes[17] = version;
            Assert.False(IkeV2DatagramInspector.TryInspect(bytes, 500, 500, true, out _));
        }

        [Fact]
        public void ReservedFlagBitsFailClosed()
        {
            var bytes = Packet();
            bytes[19] = 0x01;
            Assert.False(IkeV2DatagramInspector.TryInspect(bytes, 500, 500, true, out _));
        }

        [Fact]
        public void ZeroInitiatorSpiFailsClosed()
        {
            var bytes = Packet();
            bytes[0] = 0;
            Assert.False(IkeV2DatagramInspector.TryInspect(bytes, 500, 500, true, out _));
        }

        [Fact]
        public void ForgedGenericPayloadLengthFailsClosed()
        {
            var bytes = Packet();
            bytes[31] = 0x20;
            Assert.False(IkeV2DatagramInspector.TryInspect(bytes, 500, 500, true, out _));
        }

        [Theory]
        [InlineData((byte)46)]
        [InlineData((byte)53)]
        public void EncryptedOuterPayloadIsOpaque(byte payloadType)
        {
            var bytes = Packet(payloadType, 8);
            Assert.True(IkeV2DatagramInspector.TryInspect(bytes, 500, 500, true, out var found));
            Assert.True(found.ContainsEncryptedPayload);
            Assert.Equal(1, found.OuterPayloadCount);
        }

        [Fact]
        public void RepeatedDatagramDoesNotAssertReplayOrNegotiationSuccess()
        {
            var bytes = Packet();
            Assert.True(IkeV2DatagramInspector.TryInspect(bytes, 500, 500, true, out var first));
            Assert.True(IkeV2DatagramInspector.TryInspect(bytes, 500, 500, true, out var second));
            Assert.Equal(first, second);
        }

        [Fact]
        public void PayloadCountIsBounded()
        {
            const int count = 25;
            var bytes = new byte[28 + count * 4];
            bytes[0] = 1;
            bytes[16] = 33;
            bytes[17] = 0x20;
            bytes[18] = 34;
            bytes[19] = 0x08;
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(24, 4), (uint)bytes.Length);
            for (int i = 0; i < count; i++)
            {
                int offset = 28 + i * 4;
                bytes[offset] = i == count - 1 ? (byte)0 : (byte)33;
                bytes[offset + 3] = 4;
            }
            Assert.False(IkeV2DatagramInspector.TryInspect(bytes, 500, 500, true, out _));
        }

        [Fact]
        public void DnsDatagramCannotBeMisclassifiedAsIke()
        {
            Assert.False(IkeV2DatagramInspector.TryInspect(new byte[32], 500, 500, true, out _));
        }

        [Fact]
        public void OversizedDatagramIsRejectedBeforeParsing()
        {
            Assert.False(IkeV2DatagramInspector.TryInspect(new byte[65_536], 500, 500, true, out _));
        }

        [Fact]
        public void EncryptedMetadataDoesNotContainSpiOrCertificateBytes()
        {
            var bytes = Packet(46, 8);
            bytes[4] = 0xCC;
            Assert.True(IkeV2DatagramInspector.TryInspect(bytes, 500, 500, true, out var found));
            Assert.DoesNotContain("204", found.ToString());
            Assert.DoesNotContain("Certificate", found.ToString());
        }
    }
}
