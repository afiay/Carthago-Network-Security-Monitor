// SPDX-License-Identifier: MIT
// Synthetic RFC 3618 TLV shapes only. SOURCE CANDIDATE — UNVERIFIED; 0 executed.
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class MsdpEnvelopeInspectorTests
    {
        [Fact]
        public void ValidSourceActiveShapeReportsOnlyCounts()
        {
            Assert.True(Inspect(SourceActive(), out var result));
            Assert.True(result.IsSourceActive);
            Assert.Equal(1, result.AdvertisedSourceGroupCountUnverified);
            Assert.False(result.HasEncapsulatedIpv4Unverified);
        }

        [Fact]
        public void ValidKeepAliveIsDistinctFromSourceActive()
        {
            Assert.True(Inspect(new byte[] { 4, 0, 3 }, out var result));
            Assert.False(result.IsSourceActive);
            Assert.Equal(0, result.AdvertisedSourceGroupCountUnverified);
        }

        [Fact]
        public void NonMsdpAndReservedTypesDoNotMatch()
        {
            Assert.False(Inspect(new byte[] { 5, 0, 3 }, out _));
            Assert.False(Inspect(new byte[] { 2, 0, 3 }, out _));
            Assert.False(Inspect(new byte[] { 0x16, 0, 3 }, out _));
        }

        [Fact]
        public void DeclaredLengthMustEqualExactlyOnePdu()
        {
            byte[] data = SourceActive();
            data[2] = 19;
            Assert.False(Inspect(data, out _));
        }

        [Fact]
        public void TruncatedAndCoalescedPdusFailClosed()
        {
            Assert.False(Inspect(SourceActive().AsSpan(0, 19), out _));
            Assert.False(Inspect(SourceActive().Concat(new byte[] { 4, 0, 3 }).ToArray(), out _));
        }

        [Fact]
        public void InvalidPrefixAndNonMulticastGroupAreRejected()
        {
            byte[] data = SourceActive();
            data[11] = 24;
            Assert.False(Inspect(data, out _));
            data[11] = 32;
            data[12] = 192;
            Assert.False(Inspect(data, out _));
        }

        [Fact]
        public void MultipleSourceGroupEntriesAreBoundedAndCounted()
        {
            byte[] data = SourceActive();
            Array.Resize(ref data, 32);
            Array.Copy(data, 8, data, 20, 12);
            data[3] = 2;
            BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(1, 2), 32);
            Assert.True(Inspect(data, out var result));
            Assert.Equal(2, result.AdvertisedSourceGroupCountUnverified);
        }

        [Fact]
        public void EncapsulatedIpv4MustMatchLastSourceGroup()
        {
            byte[] data = WithEncapsulatedIpv4();
            Assert.True(Inspect(data, out var result));
            Assert.True(result.HasEncapsulatedIpv4Unverified);
            data[32] = 198; // embedded IPv4 source differs from advertised source
            Assert.False(Inspect(data, out _));
        }

        [Fact]
        public void EncapsulatedIpv4DeclaredLengthMustMatch()
        {
            byte[] data = WithEncapsulatedIpv4();
            data[23] = 21;
            Assert.False(Inspect(data, out _));
        }

        [Fact]
        public void OversizedOrUndersizedMessagesFailClosed()
        {
            Assert.False(Inspect(new byte[9193], out _));
            Assert.False(Inspect(new byte[] { 4, 0 }, out _));
            Assert.False(Inspect(new byte[] { 4, 0, 4, 0 }, out _));
        }

        [Theory]
        [InlineData(false, true, true, true)]
        [InlineData(true, false, true, true)]
        [InlineData(true, true, false, true)]
        [InlineData(true, true, true, false)]
        public void MissingTrustedBoundaryPlaintextProvenanceOrEndpointFailsClosed(
            bool complete, bool plaintext, bool provenance, bool endpoint)
        {
            Assert.False(MsdpEnvelopeInspector.TryInspect(
                SourceActive(), complete, plaintext, provenance, endpoint, out _));
        }

        [Fact]
        public void StatelessRepeatedAndConcurrentInspectionDoesNotAccumulatePeerState()
        {
            byte[] data = SourceActive();
            int failures = 0;
            Parallel.For(0, 32, _ =>
            {
                if (!Inspect(data, out var result) ||
                    result.AdvertisedSourceGroupCountUnverified != 1)
                    System.Threading.Interlocked.Increment(ref failures);
            });
            Assert.Equal(0, failures);
        }

        [Fact]
        public void ObservationHasNoRawPayloadOrAddressFields()
        {
            Assert.True(Inspect(WithEncapsulatedIpv4(), out _));
            Assert.DoesNotContain(typeof(MsdpEnvelopeObservation).GetProperties(),
                property => property.PropertyType == typeof(byte[]) ||
                            property.PropertyType == typeof(string));
        }

        private static bool Inspect(ReadOnlySpan<byte> data, out MsdpEnvelopeObservation observation) =>
            MsdpEnvelopeInspector.TryInspect(data, true, true, true, true, out observation);

        private static byte[] SourceActive()
        {
            byte[] data = new byte[20];
            data[0] = 1;
            BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(1, 2), 20);
            data[3] = 1;
            data[4] = 192; data[5] = 0; data[6] = 2; data[7] = 1; // RP
            data[11] = 32;
            data[12] = 239; data[13] = 1; data[14] = 2; data[15] = 3; // group
            data[16] = 192; data[17] = 0; data[18] = 2; data[19] = 2; // source
            return data;
        }

        private static byte[] WithEncapsulatedIpv4()
        {
            byte[] data = SourceActive();
            Array.Resize(ref data, 40);
            BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(1, 2), 40);
            data[20] = 0x45; // IPv4, IHL=5
            BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(22, 2), 20);
            Array.Copy(data, 16, data, 32, 4);
            Array.Copy(data, 12, data, 36, 4);
            return data;
        }
    }
}
