// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 2328 OSPFv2 envelopes, not authenticated routers or valid LSAs.
    public sealed class OspfV2PacketInspectorTests
    {
        private static byte[] Packet(byte type, int length)
        {
            var bytes = new byte[length];
            bytes[0] = 2; bytes[1] = type;
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2, 2), (ushort)length);
            if (type == 1 && length >= 44)
            {
                bytes[24] = 255; bytes[25] = 255; bytes[26] = 255;
                bytes[29] = 10; bytes[30] = 2; bytes[31] = 1; bytes[35] = 40;
            }
            if (type == 2 && length >= 32)
            {
                bytes[24] = 5; bytes[25] = 220; bytes[26] = 2;
            }
            if (type == 3 && length >= 36) bytes[27] = 1;
            if (type == 4 && length >= 48) bytes[27] = 1;
            SealChecksum(bytes);
            return bytes;
        }

        private static void SealChecksum(byte[] bytes)
        {
            bytes[12] = 0; bytes[13] = 0;
            uint sum = 0;
            for (int i = 0; i < bytes.Length; i += 2)
            {
                if (i is >= 16 and < 24) continue;
                ushort word = (ushort)(bytes[i] << 8);
                if (i + 1 < bytes.Length) word |= bytes[i + 1];
                sum += word;
                sum = (sum & 0xffff) + (sum >> 16);
            }
            sum = (sum & 0xffff) + (sum >> 16);
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(12, 2), (ushort)~sum);
        }

        [Theory]
        [InlineData((byte)1, 44, OspfV2PacketKind.Hello)]
        [InlineData((byte)2, 32, OspfV2PacketKind.DatabaseDescription)]
        [InlineData((byte)3, 36, OspfV2PacketKind.LinkStateRequest)]
        [InlineData((byte)4, 48, OspfV2PacketKind.LinkStateUpdate)]
        [InlineData((byte)5, 44, OspfV2PacketKind.LinkStateAcknowledgment)]
        public void StructurallyPlausiblePacketEnvelope(byte type, int length, OspfV2PacketKind expected)
        {
            Assert.True(OspfV2PacketInspector.TryInspect(Packet(type, length), 89, true, out var found));
            Assert.Equal(expected, found.Kind);
            Assert.Equal(length, found.PacketLength);
        }

        [Fact] public void CrossProtocolIpPayloadRejected()
        {
            Assert.False(OspfV2PacketInspector.TryInspect(Packet(1, 44), 17, true, out _));
        }

        [Fact] public void UnattestedIpPayloadRejected()
        {
            Assert.False(OspfV2PacketInspector.TryInspect(Packet(1, 44), 89, false, out _));
        }

        [Fact] public void OspfV3RejectedRatherThanMisclassified()
        {
            var bytes = Packet(1, 44); bytes[0] = 3; SealChecksum(bytes);
            Assert.False(OspfV2PacketInspector.TryInspect(bytes, 89, true, out _));
        }

        [Fact] public void InvalidTypeRejected()
        {
            var bytes = Packet(6, 44);
            Assert.False(OspfV2PacketInspector.TryInspect(bytes, 89, true, out _));
        }

        [Fact] public void TruncatedPacketRejected()
        {
            var bytes = Packet(1, 44);
            Assert.False(OspfV2PacketInspector.TryInspect(bytes.AsSpan(0, 43), 89, true, out _));
        }

        [Fact] public void OverlongDeclaredLengthRejected()
        {
            var bytes = Packet(1, 44); bytes[3] = 45;
            Assert.False(OspfV2PacketInspector.TryInspect(bytes, 89, true, out _));
        }

        [Fact] public void ChecksumCorruptionRejected()
        {
            var bytes = Packet(1, 44); bytes[40] ^= 0x10;
            Assert.False(OspfV2PacketInspector.TryInspect(bytes, 89, true, out _));
        }

        [Fact] public void CryptographicAuthenticationNotClaimed()
        {
            var bytes = Packet(1, 44); bytes[15] = 2; SealChecksum(bytes);
            Assert.False(OspfV2PacketInspector.TryInspect(bytes, 89, true, out _));
        }

        [Fact] public void SimplePasswordAuthenticationNotClaimed()
        {
            var bytes = Packet(1, 44); bytes[15] = 1; SealChecksum(bytes);
            Assert.False(OspfV2PacketInspector.TryInspect(bytes, 89, true, out _));
        }

        [Fact] public void ForgedUpdateLsaCountRejected()
        {
            var bytes = Packet(4, 48); bytes[27] = 2; SealChecksum(bytes);
            Assert.False(OspfV2PacketInspector.TryInspect(bytes, 89, true, out _));
        }

        [Fact] public void InvalidHelloNeighborListLengthRejected()
        {
            var bytes = Packet(1, 45);
            Assert.False(OspfV2PacketInspector.TryInspect(bytes, 89, true, out _));
        }

        [Fact] public void RepeatedPacketDoesNotEstablishAdjacency()
        {
            var bytes = Packet(1, 44);
            Assert.True(OspfV2PacketInspector.TryInspect(bytes, 89, true, out var first));
            Assert.True(OspfV2PacketInspector.TryInspect(bytes, 89, true, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public void RouterAndAreaIdentifiersNeverRetained()
        {
            var bytes = Packet(1, 44); bytes[7] = 42; bytes[11] = 99; SealChecksum(bytes);
            Assert.True(OspfV2PacketInspector.TryInspect(bytes, 89, true, out var found));
            Assert.DoesNotContain("99", found.ToString());
        }
    }
}
