// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 2784/2890 envelopes; no real tunnel keys, routing or traffic.
    public sealed class GrePacketInspectorTests
    {
        private static byte[] Ipv4(ushort flags = 0)
        {
            int header = 4 + ((flags & 0x8000) != 0 ? 4 : 0)
                + ((flags & 0x2000) != 0 ? 4 : 0)
                + ((flags & 0x1000) != 0 ? 4 : 0);
            byte[] bytes = new byte[header + 20];
            BinaryPrimitives.WriteUInt16BigEndian(bytes, flags);
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2, 2), 0x0800);
            if ((flags & 0x2000) != 0) bytes[header - ((flags & 0x1000) != 0 ? 8 : 4)] = 0xa5;
            if ((flags & 0x1000) != 0) bytes[header - 4] = 0x5a;
            bytes[header] = 0x45;
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(header + 2, 2), 20);
            if ((flags & 0x8000) != 0) SealChecksum(bytes);
            return bytes;
        }

        private static void SealChecksum(byte[] bytes)
        {
            bytes[4] = 0; bytes[5] = 0;
            uint sum = 0;
            for (int i = 0; i < bytes.Length; i += 2)
            {
                ushort word = (ushort)(bytes[i] << 8);
                if (i + 1 < bytes.Length) word |= bytes[i + 1];
                sum += word;
                sum = (sum & 0xffff) + (sum >> 16);
            }
            sum = (sum & 0xffff) + (sum >> 16);
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4, 2), (ushort)~sum);
        }

        [Theory]
        [InlineData(0x0000, false, false, false)]
        [InlineData(0x2000, false, true, false)]
        [InlineData(0x1000, false, false, true)]
        [InlineData(0x3000, false, true, true)]
        [InlineData(0x8000, true, false, false)]
        [InlineData(0xb000, true, true, true)]
        public void ValidRfc2784And2890Headers(int flags, bool checksum, bool key, bool sequence)
        {
            byte[] packet = Ipv4((ushort)flags);
            Assert.True(GrePacketInspector.TryInspect(packet, 47, true, out var found));
            Assert.Equal((ushort)0x0800, found.InnerEtherType);
            Assert.Equal(checksum, found.HasChecksum);
            Assert.Equal(key, found.HasKey);
            Assert.Equal(sequence, found.HasSequence);
        }

        [Fact] public void Ipv6EnvelopeRecognizedWithoutDecapsulation()
        {
            byte[] packet = new byte[45];
            packet[2] = 0x86; packet[3] = 0xdd;
            packet[4] = 0x60; packet[9] = 1;
            Assert.True(GrePacketInspector.TryInspect(packet, 47, true, out var found));
            Assert.Equal((ushort)0x86dd, found.InnerEtherType);
        }

        [Fact] public void TransparentEthernetEnvelopeRecognized()
        {
            byte[] packet = new byte[18];
            packet[2] = 0x65; packet[3] = 0x58;
            packet[16] = 0x08;
            Assert.True(GrePacketInspector.TryInspect(packet, 47, true, out _));
        }

        [Fact] public void WrongOuterIpProtocolRejected()
            => Assert.False(GrePacketInspector.TryInspect(Ipv4(), 17, true, out _));

        [Fact] public void UnattestedPayloadRejected()
            => Assert.False(GrePacketInspector.TryInspect(Ipv4(), 47, false, out _));

        [Fact] public void DeprecatedRoutingFlagRejected()
        {
            var bytes = Ipv4(); bytes[0] = 0x40;
            Assert.False(GrePacketInspector.TryInspect(bytes, 47, true, out _));
        }

        [Fact] public void GreVersionOneRejectedRatherThanConfusedWithPptp()
        {
            var bytes = Ipv4(); bytes[1] = 1;
            Assert.False(GrePacketInspector.TryInspect(bytes, 47, true, out _));
        }

        [Fact] public void TruncatedKeyFieldRejected()
        {
            var bytes = Ipv4(0x2000);
            Assert.False(GrePacketInspector.TryInspect(bytes.AsSpan(0, 7), 47, true, out _));
        }

        [Fact] public void CorruptChecksumRejected()
        {
            var bytes = Ipv4(0x8000); bytes[^1] ^= 1;
            Assert.False(GrePacketInspector.TryInspect(bytes, 47, true, out _));
        }

        [Fact] public void NonzeroChecksumReservedFieldRejected()
        {
            var bytes = Ipv4(0x8000); bytes[6] = 1; SealChecksum(bytes);
            Assert.False(GrePacketInspector.TryInspect(bytes, 47, true, out _));
        }

        [Fact] public void SpoofedInnerIpVersionRejected()
        {
            var bytes = Ipv4(); bytes[4] = 0x65;
            Assert.False(GrePacketInspector.TryInspect(bytes, 47, true, out _));
        }

        [Fact] public void InvalidInnerIpLengthRejected()
        {
            var bytes = Ipv4(); bytes[7] = 19;
            Assert.False(GrePacketInspector.TryInspect(bytes, 47, true, out _));
        }

        [Fact] public void OversizedEnvelopeRejected()
            => Assert.False(GrePacketInspector.TryInspect(new byte[65536], 47, true, out _));

        [Fact] public void ReplayedPacketDoesNotEstablishTunnelOrSequenceValidity()
        {
            var bytes = Ipv4(0x3000);
            Assert.True(GrePacketInspector.TryInspect(bytes, 47, true, out var first));
            Assert.True(GrePacketInspector.TryInspect(bytes, 47, true, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public void KeyAndSequenceContentsAreNotRetained()
        {
            var bytes = Ipv4(0x3000);
            Assert.True(GrePacketInspector.TryInspect(bytes, 47, true, out var found));
            Assert.DoesNotContain("165", found.ToString());
            Assert.DoesNotContain("90", found.ToString());
        }

        [Fact] public void StatelessConcurrentClassificationIsDeterministic()
        {
            var bytes = Ipv4();
            Parallel.For(0, 32, index =>
                Assert.True(GrePacketInspector.TryInspect(bytes, 47, true, out var observation)));
        }
    }
}
