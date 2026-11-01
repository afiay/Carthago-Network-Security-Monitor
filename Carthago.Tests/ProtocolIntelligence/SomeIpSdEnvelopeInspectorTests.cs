// SPDX-License-Identifier: MIT
// Synthetic AUTOSAR SOME/IP-SD message shapes; SOURCE CANDIDATE — UNVERIFIED.
// Tests authored, never executed. No real captures or sensitive identifiers.
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class SomeIpSdEnvelopeInspectorTests
    {
        [Fact]
        public void ValidFindServiceReportsOnlyUnverifiedShape()
        {
            Assert.True(Inspect(Message(new[] { Entry(0x00) }, Array.Empty<byte[]>()),
                out var result));
            Assert.Equal(1, result.FindServiceCountUnverified);
            Assert.Equal(0, result.OfferServiceCountUnverified);
            Assert.Equal(0, result.OptionCount);
        }

        [Fact]
        public void OfferWithEndpointOptionCountsButDoesNotExposeEndpoint()
        {
            byte[] offer = Entry(0x01);
            offer[3] = 0x10; // First option run has one element at index zero.
            Assert.True(Inspect(Message(new[] { offer }, new[] { Ipv4EndpointOption() }),
                out var result));
            Assert.Equal(1, result.OfferServiceCountUnverified);
            Assert.True(result.HasEndpointOption);
            Assert.Equal(1, result.OptionCount);
        }

        [Fact]
        public void SubscribeAndAckAreNotConfusedWithOffers()
        {
            byte[] message = Message(new[] { Entry(0x06), Entry(0x07) },
                Array.Empty<byte[]>());
            Assert.True(Inspect(message, out var result));
            Assert.Equal(1, result.SubscribeEventgroupCountUnverified);
            Assert.Equal(1, result.SubscribeAckCountUnverified);
            Assert.Equal(0, result.OfferServiceCountUnverified);
        }

        [Fact]
        public void ZeroTtlOfferIsOnlyAnUnverifiedStopOfferShape()
        {
            Assert.True(Inspect(Message(new[] { Entry(0x01, ttl: 0) },
                Array.Empty<byte[]>()), out var result));
            Assert.Equal(1, result.StopOfferCountUnverified);
        }

        [Theory]
        [InlineData(0, 0x01)]
        [InlineData(2, 0x00)]
        [InlineData(12, 0x02)]
        [InlineData(13, 0x03)]
        [InlineData(14, 0x22)]
        [InlineData(15, 0x01)]
        public void WrongServiceMethodVersionTypeOrReturnCodeFailsClosed(int index, byte value)
        {
            byte[] message = Message(new[] { Entry(0x00) }, Array.Empty<byte[]>());
            message[index] = value;
            Assert.False(Inspect(message, out _));
        }

        [Fact]
        public void DeclaredLengthCannotTriggerAllocationOrAcceptTrailingBytes()
        {
            byte[] message = Message(new[] { Entry(0x00) }, Array.Empty<byte[]>());
            BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(4, 4), uint.MaxValue);
            Assert.False(Inspect(message, out _));
            byte[] extra = Message(new[] { Entry(0x00) }, Array.Empty<byte[]>())
                .Concat(new byte[] { 0 }).ToArray();
            Assert.False(Inspect(extra, out _));
        }

        [Fact]
        public void TruncatedOrOversizedDatagramFailsClosed()
        {
            byte[] message = Message(new[] { Entry(0x00) }, Array.Empty<byte[]>());
            Assert.False(Inspect(message.AsSpan(0, message.Length - 1), out _));
            Assert.False(Inspect(new byte[4097], out _));
            Assert.False(Inspect(new byte[27], out _));
        }

        [Fact]
        public void EntryLengthMustBeAlignedAndFitBeforeOptionsLength()
        {
            byte[] message = Message(new[] { Entry(0x00) }, Array.Empty<byte[]>());
            BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(20, 4), 15);
            Assert.False(Inspect(message, out _));
            BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(20, 4), uint.MaxValue);
            Assert.False(Inspect(message, out _));
        }

        [Fact]
        public void UnknownEntryTypeAndOutOfRangeOptionReferenceFailClosed()
        {
            byte[] unknown = Entry(0x09);
            Assert.False(Inspect(Message(new[] { unknown }, Array.Empty<byte[]>()),
                out _));
            byte[] entry = Entry(0x01);
            entry[3] = 0x10;
            Assert.False(Inspect(Message(new[] { entry }, Array.Empty<byte[]>()),
                out _));
        }

        [Fact]
        public void MalformedOptionLengthAndReservedByteFailClosed()
        {
            byte[] option = Ipv4EndpointOption();
            option[1] = 0xff;
            Assert.False(Inspect(Message(new[] { Entry(0x01) }, new[] { option }),
                out _));
            option = Ipv4EndpointOption();
            option[8] = 1;
            Assert.False(Inspect(Message(new[] { Entry(0x01) }, new[] { option }),
                out _));
        }

        [Fact]
        public void UnsupportedEndpointTransportFailsClosed()
        {
            byte[] option = Ipv4EndpointOption();
            option[9] = 0;
            Assert.False(Inspect(Message(new[] { Entry(0x01) }, new[] { option }),
                out _));
        }

        [Fact]
        public void UnknownOptionIsOpaqueAndStillCounted()
        {
            byte[] option = { 0, 1, 0xee, 0xff };
            Assert.True(Inspect(Message(new[] { Entry(0x00) }, new[] { option }),
                out var result));
            Assert.Equal(1, result.OptionCount);
            Assert.False(result.HasEndpointOption);
        }

        [Fact]
        public void ExcessiveOptionCountFailsClosedWithoutGrowingState()
        {
            byte[][] options = Enumerable.Range(0, 65)
                .Select(_ => new byte[] { 0, 1, 0xee, 0 }).ToArray();
            Assert.False(Inspect(Message(new[] { Entry(0x00) }, options), out _));
        }

        [Fact]
        public void ReservedFlagsAndReservedEventgroupBitsFailClosed()
        {
            byte[] message = Message(new[] { Entry(0x00) },
                Array.Empty<byte[]>(), flags: 0x01);
            Assert.False(Inspect(message, out _));
            byte[] entry = Entry(0x06);
            entry[13] = 0x10;
            Assert.False(Inspect(Message(new[] { entry }, Array.Empty<byte[]>()),
                out _));
        }

        [Theory]
        [InlineData(false, true, true, true, true)]
        [InlineData(true, false, true, true, true)]
        [InlineData(true, true, false, true, true)]
        [InlineData(true, true, true, false, true)]
        [InlineData(true, true, true, true, false)]
        public void MissingCompleteUdpUnfragmentedPlaintextEndpointOrProvenanceFailsClosed(
            bool complete, bool unfragmented, bool plaintext, bool endpoint,
            bool provenance)
        {
            Assert.False(SomeIpSdEnvelopeInspector.TryInspect(
                Message(new[] { Entry(0x00) }, Array.Empty<byte[]>()),
                complete, unfragmented, plaintext, endpoint, provenance, out _));
        }

        [Fact]
        public void EncryptedOrUntrustedBytesCannotBeDeclaredObservable()
        {
            Assert.False(SomeIpSdEnvelopeInspector.TryInspect(
                Message(new[] { Entry(0x01) }, Array.Empty<byte[]>()),
                true, true, false, true, true, out _));
        }

        [Fact]
        public void ConcurrentRepeatedInspectionIsStateless()
        {
            byte[] message = Message(new[] { Entry(0x01) }, Array.Empty<byte[]>());
            int failures = 0;
            Parallel.For(0, 32, _ =>
            {
                if (!Inspect(message, out var result) ||
                    result.OfferServiceCountUnverified != 1)
                    Interlocked.Increment(ref failures);
            });
            Assert.Equal(0, failures);
        }

        [Fact]
        public void ObservationHasNoAddressIdentifierOrRawPayloadFields()
        {
            Assert.True(Inspect(Message(new[] { Entry(0x01) },
                new[] { Ipv4EndpointOption() }), out _));
            Assert.DoesNotContain(typeof(SomeIpSdEnvelopeObservation).GetProperties(),
                property => property.PropertyType == typeof(byte[]) ||
                            property.PropertyType == typeof(string) ||
                            property.PropertyType == typeof(ReadOnlyMemory<byte>));
        }

        private static bool Inspect(ReadOnlySpan<byte> data,
            out SomeIpSdEnvelopeObservation observation) =>
            SomeIpSdEnvelopeInspector.TryInspect(data, true, true, true, true, true,
                out observation);

        private static byte[] Entry(byte type, byte ttl = 60)
        {
            byte[] entry = new byte[16];
            entry[0] = type;
            entry[4] = 0x12;
            entry[5] = 0x34;
            entry[7] = 1;
            entry[8] = 1;
            entry[11] = ttl;
            return entry;
        }

        private static byte[] Ipv4EndpointOption() =>
            new byte[] { 0, 9, 4, 0, 192, 0, 2, 1, 0, 17, 0x77, 0x1a };

        private static byte[] Message(byte[][] entries, byte[][] options,
            byte flags = 0)
        {
            int entriesBytes = entries.Sum(entry => entry.Length);
            int optionsBytes = options.Sum(option => option.Length);
            byte[] result = new byte[28 + entriesBytes + optionsBytes];
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(0, 2), 0xffff);
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2, 2), 0x8100);
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(4, 4),
                checked((uint)(result.Length - 8)));
            result[12] = 1; result[13] = 1; result[14] = 2;
            result[16] = flags;
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(20, 4),
                checked((uint)entriesBytes));
            int offset = 24;
            foreach (byte[] entry in entries)
            {
                Array.Copy(entry, 0, result, offset, entry.Length);
                offset += entry.Length;
            }
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset, 4),
                checked((uint)optionsBytes));
            offset += 4;
            foreach (byte[] option in options)
            {
                Array.Copy(option, 0, result, offset, option.Length);
                offset += option.Length;
            }
            return result;
        }
    }
}
