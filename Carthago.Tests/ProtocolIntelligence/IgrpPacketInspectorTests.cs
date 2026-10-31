// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic, non-secret IGRP v1 protocol-9 envelopes based on Cisco's
    // "An Introduction to IGRP"; no live capture, network I/O or replay.
    public sealed class IgrpPacketInspectorTests
    {
        private static byte[] Packet(bool update = true, ushort interior = 1,
            ushort system = 0, ushort exterior = 0, byte edition = 0)
        {
            int count = update ? interior + system + exterior : 0;
            var bytes = new byte[12 + count * 14];
            bytes[0] = update ? (byte)0x11 : (byte)0x12;
            bytes[1] = edition;
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2, 2), 123);
            if (update)
            {
                BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4, 2), interior);
                BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6, 2), system);
                BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8, 2), exterior);
            }
            FixChecksum(bytes);
            return bytes;
        }

        private static void FixChecksum(byte[] bytes)
        {
            bytes[10] = bytes[11] = 0;
            uint sum = 0;
            for (int i = 0; i + 1 < bytes.Length; i += 2)
            {
                sum += BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(i, 2));
                sum = (sum & 0xffff) + (sum >> 16);
            }
            sum = (sum & 0xffff) + (sum >> 16);
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(10, 2), (ushort)~sum);
        }

        private static bool Inspect(byte[] bytes, out IgrpObservation result,
            byte ipProtocol = 9, bool complete = true, bool trusted = true)
            => IgrpPacketInspector.TryInspect(bytes, ipProtocol, complete, trusted, out result);

        [Fact]
        public void ValidRequestHasNoRoutes()
        {
            Assert.True(Inspect(Packet(update: false), out var found));
            Assert.True(found.IsRequest);
            Assert.Equal(123, found.AutonomousSystem);
            Assert.Equal(0, found.TotalRoutes);
        }

        [Theory]
        [InlineData(1, 0, 0)]
        [InlineData(1, 2, 3)]
        [InlineData(0, 0, 104)]
        public void ValidUpdateHasBoundedCounts(int interior, int system, int exterior)
        {
            Assert.True(Inspect(Packet(interior: (ushort)interior,
                system: (ushort)system, exterior: (ushort)exterior), out var found));
            Assert.Equal(interior + system + exterior, found.TotalRoutes);
            Assert.Equal(1, found.Opcode);
        }

        [Fact]
        public void EditionIsMetadataNotEvidenceOfAcceptedUpdate()
        {
            Assert.True(Inspect(Packet(edition: 255), out var found));
            Assert.Equal(255, found.Edition);
        }

        [Theory]
        [InlineData(6)]
        [InlineData(17)]
        [InlineData(88)]
        public void CrossProtocolPayloadRejectedEvenIfBytesMatch(byte protocol)
        {
            Assert.False(Inspect(Packet(), out _, ipProtocol: protocol));
        }

        [Fact]
        public void RandomNonIgrpPayloadRejected()
        {
            Assert.False(Inspect(Enumerable.Repeat((byte)0x55, 26).ToArray(), out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(11)]
        public void TruncatedHeaderRejected(int length)
        {
            Assert.False(Inspect(Packet(update: false).Take(length).ToArray(), out _));
        }

        [Fact]
        public void TruncatedRouteRejected()
        {
            Assert.False(Inspect(Packet().Take(25).ToArray(), out _));
        }

        [Fact]
        public void TrailingBytesRejectedEvenWithValidChecksum()
        {
            var bytes = Packet();
            Array.Resize(ref bytes, bytes.Length + 2);
            FixChecksum(bytes);
            Assert.False(Inspect(bytes, out _));
        }

        [Fact]
        public void InvalidVersionRejected()
        {
            var bytes = Packet();
            bytes[0] = 0x21; FixChecksum(bytes);
            Assert.False(Inspect(bytes, out _));
        }

        [Fact]
        public void InvalidOpcodeRejected()
        {
            var bytes = Packet();
            bytes[0] = 0x13; FixChecksum(bytes);
            Assert.False(Inspect(bytes, out _));
        }

        [Fact]
        public void CorruptedChecksumRejected()
        {
            var bytes = Packet();
            bytes[12] ^= 0x40;
            Assert.False(Inspect(bytes, out _));
        }

        [Fact]
        public void UpdateRouteCountMismatchRejected()
        {
            var bytes = Packet();
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4, 2), 2);
            FixChecksum(bytes);
            Assert.False(Inspect(bytes, out _));
        }

        [Fact]
        public void OversizedRouteCountRejected()
        {
            Assert.False(Inspect(Packet(interior: 105), out _));
        }

        [Fact]
        public void EmptyUpdateRejected()
        {
            Assert.False(Inspect(Packet(interior: 0), out _));
        }

        [Fact]
        public void RequestWithEditionRejected()
        {
            Assert.False(Inspect(Packet(update: false, edition: 1), out _));
        }

        [Fact]
        public void RequestWithRouteDataRejected()
        {
            var bytes = Packet();
            bytes[0] = 0x12; FixChecksum(bytes);
            Assert.False(Inspect(bytes, out _));
        }

        [Fact]
        public void UntrustedSourceFailsClosed()
        {
            Assert.False(Inspect(Packet(), out var found, trusted: false));
            Assert.Equal(default, found);
        }

        [Fact]
        public void FragmentOrIncompleteDatagramFailsClosed()
        {
            Assert.False(Inspect(Packet(), out _, complete: false));
        }

        [Fact]
        public void NoRouteAddressesOrPayloadAreExposed()
        {
            Assert.True(Inspect(Packet(), out var found));
            var names = typeof(IgrpObservation).GetProperties()
                .Select(property => property.Name).ToArray();
            Assert.DoesNotContain(names, name => name.Contains("Address", StringComparison.Ordinal));
            Assert.DoesNotContain(names, name => name.Contains("Payload", StringComparison.Ordinal));
            Assert.Equal(1, found.TotalRoutes);
        }

        [Fact]
        public void RepeatedAndOutOfOrderEnvelopesDoNotAccumulateState()
        {
            var a = Packet(edition: 2);
            var b = Packet(edition: 1);
            Assert.True(Inspect(a, out var first));
            Assert.True(Inspect(b, out var second));
            Assert.True(Inspect(a, out var again));
            Assert.Equal(first, again);
            Assert.Equal(1, second.Edition);
        }

        [Fact]
        public async Task ConcurrentCallsHaveIndependentResults()
        {
            var packets = Enumerable.Range(1, 20)
                .Select(i => Packet(edition: (byte)i)).ToArray();
            var results = await Task.WhenAll(packets.Select((p, i) => Task.Run(() =>
            {
                var accepted = Inspect(p, out var observation);
                return accepted && observation.Edition == i + 1;
            })));
            Assert.All(results, Assert.True);
        }
    }
}
