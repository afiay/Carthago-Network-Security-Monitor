// SPDX-License-Identifier: MIT
// Synthetic ZEPv2 UDP envelope fixtures based on the documented 32-byte
// Data / 8-byte Ack layouts; no captured radio frames or private payloads.
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class ZepV2EnvelopeInspectorTests
    {
        private static byte[] Data(
            int channel = 15, int frameLength = 1, int mode = 1,
            uint sequence = 0x01020304)
        {
            var bytes = new byte[32 + frameLength];
            bytes[0] = (byte)'E';
            bytes[1] = (byte)'X';
            bytes[2] = 2;
            bytes[3] = 1;
            bytes[4] = (byte)channel;
            bytes[5] = 0x12;
            bytes[6] = 0x34;
            bytes[7] = (byte)mode;
            bytes[8] = 0x5a;
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(17, 4), sequence);
            bytes[31] = (byte)frameLength;
            for (int i = 32; i < bytes.Length; i++)
                bytes[i] = 0xa5;
            return bytes;
        }

        private static byte[] Ack(uint sequence = 0x01020304)
        {
            var bytes = new byte[8];
            bytes[0] = (byte)'E';
            bytes[1] = (byte)'X';
            bytes[2] = 2;
            bytes[3] = 2;
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(4, 4), sequence);
            return bytes;
        }

        private static bool Inspect(
            ReadOnlySpan<byte> datagram, out ZepEnvelopeObservation observation)
            => ZepV2EnvelopeInspector.TryInspect(
                datagram, true, true, true, true, out observation);

        [Theory]
        [InlineData(11)]
        [InlineData(15)]
        [InlineData(26)]
        public void RecognizesBoundedDataOnSupportedChannels(int channel)
        {
            Assert.True(Inspect(Data(channel: channel), out var observation));
            Assert.Equal((byte)2, observation.Version);
            Assert.Equal(ZepPacketKind.Data, observation.PacketKind);
            Assert.Equal((byte)channel, observation.Channel);
            Assert.Equal((byte)1, observation.FrameLength);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(127)]
        public void RecognizesExactFrameLengthBoundaries(int frameLength)
        {
            Assert.True(Inspect(Data(frameLength: frameLength), out var observation));
            Assert.Equal((byte)frameLength, observation.FrameLength);
        }

        [Fact]
        public void RecognizesEightByteAcknowledgementWithoutRadioFrame()
        {
            Assert.True(Inspect(Ack(), out var observation));
            Assert.Equal(ZepPacketKind.Acknowledgement, observation.PacketKind);
            Assert.Null(observation.Channel);
            Assert.Equal((byte)0, observation.FrameLength);
            Assert.Equal(0x01020304u, observation.SequenceNumber);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(0x5a)]
        public void NonZepMagicFailsClosed(int firstByte)
        {
            var bytes = Data();
            bytes[0] = (byte)firstByte;
            Assert.False(Inspect(bytes, out _));
        }

        [Theory]
        [InlineData(1, 1)]
        [InlineData(3, 1)]
        [InlineData(2, 0)]
        [InlineData(2, 3)]
        public void UnsupportedVersionsAndTypesFailClosed(int version, int type)
        {
            var bytes = Data();
            bytes[2] = (byte)version;
            bytes[3] = (byte)type;
            Assert.False(Inspect(bytes, out _));
        }

        [Fact]
        public void EveryTruncatedDataEnvelopeFailsClosed()
        {
            var complete = Data();
            for (int length = 0; length < complete.Length; length++)
                Assert.False(Inspect(complete.AsSpan(0, length), out _));
        }

        [Fact]
        public void EveryTruncatedAcknowledgementFailsClosed()
        {
            var complete = Ack();
            for (int length = 0; length < complete.Length; length++)
                Assert.False(Inspect(complete.AsSpan(0, length), out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(2)]
        [InlineData(128)]
        public void SpoofedOrUnsupportedDeclaredLengthsFailClosed(int declared)
        {
            var bytes = Data();
            bytes[31] = (byte)declared;
            Assert.False(Inspect(bytes, out _));
        }

        [Fact]
        public void DatagramOverMaximumBoundFailsClosed()
        {
            var bytes = Data(frameLength: 127);
            Assert.True(Inspect(bytes, out _));
            Array.Resize(ref bytes, 160);
            Assert.False(Inspect(bytes, out _));
        }

        [Theory]
        [InlineData(27, 1)]
        [InlineData(15, 2)]
        public void UnsupportedChannelOrCrcLqiModeFailsClosed(int channel, int mode)
            => Assert.False(Inspect(Data(channel: channel, mode: mode), out _));

        [Fact]
        public void AcknowledgementCannotCarryTrailingBytes()
        {
            var bytes = Ack();
            Array.Resize(ref bytes, 9);
            Assert.False(Inspect(bytes, out _));
        }

        [Fact]
        public void SequenceNumberUsesNetworkByteOrder()
        {
            Assert.True(Inspect(Data(sequence: 0x01020304), out var observation));
            Assert.Equal(0x01020304u, observation.SequenceNumber);
            Assert.True(Inspect(Ack(sequence: 0x04030201), out var ack));
            Assert.Equal(0x04030201u, ack.SequenceNumber);
        }

        [Fact]
        public void DuplicatesAndOutOfOrderSequencesAreStateless()
        {
            Assert.True(Inspect(Data(sequence: 7), out var first));
            Assert.True(Inspect(Data(sequence: 2), out var earlier));
            Assert.True(Inspect(Data(sequence: 7), out var repeated));
            Assert.Equal(first, repeated);
            Assert.NotEqual(first.SequenceNumber, earlier.SequenceNumber);
        }

        [Fact]
        public async Task ConcurrentCallsAreDeterministic()
        {
            var bytes = Data(sequence: 41);
            var observations = await Task.WhenAll(
                Enumerable.Range(0, 32).Select(_ => Task.Run(() =>
                {
                    Assert.True(Inspect(bytes, out var observation));
                    return observation;
                })));
            Assert.All(observations, item => Assert.Equal(observations[0], item));
        }

        [Theory]
        [InlineData(false, true, true, true)]
        [InlineData(true, false, true, true)]
        [InlineData(true, true, false, true)]
        [InlineData(true, true, true, false)]
        public void AllFourAttestationsAreMandatory(
            bool complete, bool endpoint, bool plaintext, bool provenance)
        {
            Assert.False(ZepV2EnvelopeInspector.TryInspect(
                Data(), complete, endpoint, plaintext, provenance, out var rejected));
            Assert.Equal(default(ZepEnvelopeObservation), rejected);
        }

        [Fact]
        public void PayloadAndDeviceIdentityAreNotRetained()
        {
            var first = Data();
            var second = Data();
            first[32] = 0x01;
            second[32] = 0xff;
            second[5] = 0xff;
            second[6] = 0xff;
            second[8] = 0x00;
            Assert.True(Inspect(first, out var a));
            Assert.True(Inspect(second, out var b));
            Assert.Equal(a, b);
            Assert.DoesNotContain(typeof(ZepEnvelopeObservation).GetProperties(),
                property => property.PropertyType == typeof(string) ||
                            property.PropertyType == typeof(byte[]));
        }

        [Fact]
        public void FailedParseDoesNotReusePreviousObservation()
        {
            Assert.True(Inspect(Data(), out _));
            var bytes = Data();
            bytes[0] = 0;
            Assert.False(Inspect(bytes, out var rejected));
            Assert.Equal(default(ZepEnvelopeObservation), rejected);
        }

        [Fact]
        public void SyntheticOpaqueInnerFrameIsNotClaimedValidOrAuthenticated()
        {
            var bytes = Data(frameLength: 4);
            bytes.AsSpan(32).Clear();
            Assert.True(Inspect(bytes, out var observation));
            Assert.Equal((byte)4, observation.FrameLength);
        }
    }
}
