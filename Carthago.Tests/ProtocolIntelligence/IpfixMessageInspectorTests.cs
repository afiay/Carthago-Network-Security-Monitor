// SPDX-License-Identifier: MIT
// Synthetic RFC 7011 envelope fixtures; source-only, not executed.
using System;
using System.Buffers.Binary;
using System.Linq;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class IpfixMessageInspectorTests
    {
        [Fact]
        public void CompleteTemplateAndDataEnvelopeIsClassifiedWithoutDecodingRecords()
        {
            byte[] template = Set(2, 1, 0, 0, 1, 0, 8, 0, 4);
            byte[] data = Set(256, 0xde, 0xad, 0xbe, 0xef);
            byte[] message = Message(template, data);
            Assert.True(Inspect(message, out var observation));
            Assert.Equal(2, observation.SetCount);
            Assert.Equal(1, observation.TemplateSetCount);
            Assert.Equal(1, observation.DataSetCount);
            Assert.Equal(0, observation.OptionsTemplateSetCount);
            Assert.Equal((uint)3, observation.ObservationDomainIdUnverified);
            Assert.Equal((uint)2, observation.SequenceNumberUnverified);
        }

        [Fact]
        public void OptionsTemplateAndDataSetAreOnlyEnvelopeCounted()
        {
            byte[] options = Set(3, 1, 1, 0, 1, 0, 1, 0, 8, 0, 4);
            byte[] data = Set(257, 1, 2, 3, 4);
            Assert.True(Inspect(Message(options, data), out var result));
            Assert.Equal(1, result.OptionsTemplateSetCount);
            Assert.Equal(1, result.DataSetCount);
        }

        [Fact]
        public void HeaderOnlyMessageIsValidPerRfc7011()
        {
            Assert.True(Inspect(Message(), out var result));
            Assert.Equal(0, result.SetCount);
        }

        [Fact]
        public void NetFlowV9IsNotMisclassifiedAsIpfixV10()
        {
            byte[] message = Message();
            BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(0, 2), 9);
            Assert.False(Inspect(message, out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(4)]
        [InlineData(255)]
        public void ReservedSetIdsAreRejected(int setId)
        {
            Assert.False(Inspect(Message(Set((ushort)setId, 1, 2, 3, 4)), out _));
        }

        [Fact]
        public void DeclaredLengthMustMatchExactlyOneCompleteMessage()
        {
            byte[] message = Message(Set(256, 1, 2, 3, 4));
            BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2, 2), (ushort)(message.Length - 1));
            Assert.False(Inspect(message, out _));
        }

        [Fact]
        public void TruncatedSetFailsClosed()
        {
            byte[] message = Message(Set(256, 1, 2, 3, 4));
            BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(18, 2), 20);
            Assert.False(Inspect(message, out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(3)]
        public void UndersizedSetLengthFailsClosed(int setLength)
        {
            byte[] message = Message(Set(256, 1, 2, 3, 4));
            BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(18, 2), (ushort)setLength);
            Assert.False(Inspect(message, out _));
        }

        [Fact]
        public void BoundedSetWalkRejectsExcessiveSetCount()
        {
            byte[][] sets = Enumerable.Range(0, 4097).Select(_ => Set(256)).ToArray();
            Assert.False(Inspect(Message(sets), out _));
        }

        [Theory]
        [InlineData(false, true, true)]
        [InlineData(true, false, true)]
        [InlineData(true, true, false)]
        public void MissingBoundaryPlaintextOrCaptureProvenanceFailsClosed(
            bool boundary, bool plaintext, bool provenance)
        {
            Assert.False(IpfixMessageInspector.TryInspect(
                Message(), boundary, plaintext, provenance, out _));
        }

        [Fact]
        public void ObservationDoesNotRetainUntrustedPayloadOrRawRecords()
        {
            byte[] message = Message(Set(256, 0xfa, 0xfb, 0xfc, 0xfd));
            Assert.True(Inspect(message, out var result));
            Assert.Equal(1, result.DataSetCount);
            Assert.DoesNotContain(typeof(IpfixEnvelopeObservation).GetProperties(),
                property => property.PropertyType == typeof(byte[]) ||
                            property.PropertyType == typeof(string));
        }

        [Fact]
        public void OpaqueDataSetContentsDoNotClaimRecordValidity()
        {
            Assert.True(Inspect(Message(Set(256, 0xff, 0xff, 0xff, 0xff)), out var result));
            Assert.Equal(1, result.DataSetCount);
        }

        private static bool Inspect(byte[] message, out IpfixEnvelopeObservation result) =>
            IpfixMessageInspector.TryInspect(message, true, true, true, out result);

        private static byte[] Message(params byte[][] sets)
        {
            int length = 16 + sets.Sum(set => set.Length);
            byte[] result = new byte[length];
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(0, 2), 10);
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2, 2), checked((ushort)length));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(4, 4), 1);
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8, 4), 2);
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(12, 4), 3);
            int offset = 16;
            foreach (byte[] set in sets)
            {
                set.CopyTo(result, offset);
                offset += set.Length;
            }
            return result;
        }

        private static byte[] Set(ushort setId, params byte[] payload)
        {
            byte[] result = new byte[4 + payload.Length];
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(0, 2), setId);
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2, 2), checked((ushort)result.Length));
            payload.CopyTo(result, 4);
            return result;
        }
    }
}
