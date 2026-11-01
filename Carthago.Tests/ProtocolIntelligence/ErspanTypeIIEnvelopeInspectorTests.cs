// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic, non-secret ERSPAN Type II envelopes modeled from
    // draft-foschiano-erspan-02, section 4.2. Never executed in this GA.
    public sealed class ErspanTypeIIEnvelopeInspectorTests
    {
        private static byte[] Envelope(ushort vlan = 10, byte cos = 2,
            bool truncated = false, uint sequence = 0x01020304,
            int mirroredBytes = 14)
        {
            byte[] bytes = new byte[16 + mirroredBytes];
            bytes[0] = 0x10; // GRE S=1; all other flags zero.
            bytes[2] = 0x88; bytes[3] = 0xbe;
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(4, 4), sequence);
            bytes[8] = (byte)(0x10 | (vlan >> 8));
            bytes[9] = (byte)vlan;
            bytes[10] = (byte)((cos << 5) | (truncated ? 4 : 0) | 1);
            bytes[11] = 1; // session 257
            bytes[13] = 1; bytes[14] = 0x23; bytes[15] = 0x45;
            if (mirroredBytes >= 14)
            {
                bytes[16] = 0x02; bytes[22] = 0x04; // synthetic MAC bytes
                bytes[28] = 0x08; bytes[29] = 0x00; // Ethernet-II IPv4
            }
            return bytes;
        }

        private static bool Inspect(ReadOnlySpan<byte> bytes,
            out ErspanTypeIIObservation result) =>
            ErspanTypeIIEnvelopeInspector.TryInspect(
                bytes, 47, true, true, true, true, out result);

        [Theory]
        [InlineData(1, 0)]
        [InlineData(4094, 7)]
        [InlineData(0, 3)]
        public void ValidTypeIIGreAndHeaderFields(int vlan, int cos)
        {
            byte[] bytes = Envelope((ushort)vlan, (byte)cos);
            Assert.True(Inspect(bytes, out var result));
            Assert.Equal((ushort)vlan, result.VlanId);
            Assert.Equal((byte)cos, result.ClassOfService);
            Assert.Equal((ushort)257, result.SessionId);
            Assert.Equal((uint)0x12345, result.PortIndex);
            Assert.Equal((uint)0x01020304, result.SequenceNumber);
            Assert.Equal((ushort)0x0800, result.MirroredEtherType);
        }

        [Fact] public void ExactMinimumMirroredEthernetBoundaryAccepted()
        {
            Assert.True(Inspect(Envelope(), out var result));
            Assert.Equal(14, result.MirroredFrameBytes);
        }

        [Fact] public void TruncationFlagIsReportedWithoutAssumingAttack()
        {
            Assert.True(Inspect(Envelope(truncated: true), out var result));
            Assert.True(result.Truncated);
            Assert.Equal((byte)0, result.EncapsulationKind);
        }

        [Fact] public void TypeIIIProtocolIsNotMisclassifiedAsTypeII()
        {
            var bytes = Envelope(); bytes[2] = 0x22; bytes[3] = 0xeb;
            Assert.False(Inspect(bytes, out _));
        }

        [Fact] public void TypeIWithoutSequenceIsNotMisclassified()
        {
            var bytes = Envelope(); bytes[0] = 0;
            Assert.False(Inspect(bytes, out _));
        }

        [Fact] public void KeyedGreVariantIsRejected()
        {
            var bytes = Envelope(); bytes[0] = 0x30;
            Assert.False(Inspect(bytes, out _));
        }

        [Fact] public void WrongOuterIpProtocolIsRejected()
        {
            Assert.False(ErspanTypeIIEnvelopeInspector.TryInspect(
                Envelope(), 17, true, true, true, true, out _));
        }

        [Fact] public void UnsupportedErspanVersionIsRejected()
        {
            var bytes = Envelope(); bytes[8] = 0x20;
            Assert.False(Inspect(bytes, out _));
        }

        [Fact] public void NonzeroReservedHeaderBitsAreRejected()
        {
            var bytes = Envelope(); bytes[12] = 1;
            Assert.False(Inspect(bytes, out _));
            bytes = Envelope(); bytes[13] |= 0x80;
            Assert.False(Inspect(bytes, out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(7)]
        [InlineData(15)]
        [InlineData(29)]
        public void TruncatedGreHeaderOrMirroredFrameFailsClosed(int count)
        {
            Assert.False(Inspect(Envelope().AsSpan(0, count), out _));
        }

        [Fact] public void ShortMirroredEthernetFrameIsRejected()
        {
            Assert.False(Inspect(Envelope(mirroredBytes: 13), out _));
        }

        [Fact] public void NonEthernetIIFrameIsConservativelyRejected()
        {
            var bytes = Envelope(); bytes[28] = 0x00; bytes[29] = 0x2e;
            Assert.False(Inspect(bytes, out _));
        }

        [Fact] public void OversizedGreEnvelopeFailsBoundedLimit()
        {
            Assert.False(Inspect(new byte[16385], out _));
        }

        [Fact] public void UnattestedCompleteIpBoundaryIsRejected()
        {
            Assert.False(ErspanTypeIIEnvelopeInspector.TryInspect(
                Envelope(), 47, false, true, true, true, out _));
        }

        [Fact] public void UnverifiedMirrorEndpointIsRejected()
        {
            Assert.False(ErspanTypeIIEnvelopeInspector.TryInspect(
                Envelope(), 47, true, false, true, true, out _));
        }

        [Fact] public void UnverifiedPlaintextIsRejected()
        {
            Assert.False(ErspanTypeIIEnvelopeInspector.TryInspect(
                Envelope(), 47, true, true, false, true, out _));
        }

        [Fact] public void UnverifiedCaptureProvenanceIsRejected()
        {
            Assert.False(ErspanTypeIIEnvelopeInspector.TryInspect(
                Envelope(), 47, true, true, true, false, out _));
        }

        [Fact] public void SpoofedSessionIsMetadataNotAuthentication()
        {
            var bytes = Envelope(); bytes[11] = 0xfe;
            Assert.True(Inspect(bytes, out var result));
            Assert.Equal((ushort)510, result.SessionId);
        }

        [Fact] public void DuplicateAndReorderedSequenceHaveNoImplicitReplayVerdict()
        {
            var high = Envelope(sequence: 42);
            var low = Envelope(sequence: 41);
            Assert.True(Inspect(high, out var first));
            Assert.True(Inspect(high, out var repeated));
            Assert.True(Inspect(low, out var reordered));
            Assert.Equal(first, repeated);
            Assert.Equal((uint)41, reordered.SequenceNumber);
        }

        [Fact] public void ConcurrentStatelessInspectionsAreDeterministic()
        {
            var bytes = Envelope();
            Parallel.For(0, 32, _ =>
            {
                Assert.True(Inspect(bytes, out var result));
                Assert.Equal((ushort)257, result.SessionId);
            });
        }

        [Fact] public void ObservationHasNoRawFrameOrMacAddressFields()
        {
            Assert.True(Inspect(Envelope(), out _));
            foreach (var property in typeof(ErspanTypeIIObservation).GetProperties())
            {
                Assert.NotEqual(typeof(byte[]), property.PropertyType);
                Assert.NotEqual(typeof(string), property.PropertyType);
                Assert.DoesNotContain("Mac", property.Name);
                Assert.DoesNotContain("Payload", property.Name);
            }
        }

        [Fact] public void FailedParseClearsPriorObservation()
        {
            var result = new ErspanTypeIIObservation(1, 2, 0, false, 3, 4, 5, 6, 7);
            var bytes = Envelope(); bytes[0] = 0xff;
            Assert.False(Inspect(bytes, out result));
            Assert.Equal(default, result);
        }
    }
}
