// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic DMTF DSP0136 ASF envelopes. Never real BMC command evidence.
    public sealed class RmcpAsfEnvelopeInspectorTests
    {
        private static byte[] Asf(byte type = 0x80, int dataLength = 0,
            byte sequence = 1, byte tag = 7)
        {
            var bytes = new byte[12 + dataLength];
            bytes[0] = 6; bytes[1] = 0; bytes[2] = sequence; bytes[3] = 6;
            bytes[6] = 0x11; bytes[7] = 0xbe; // IANA enterprise 4542
            bytes[8] = type; bytes[9] = tag; bytes[10] = 0;
            bytes[11] = (byte)dataLength;
            return bytes;
        }

        private static bool Inspect(byte[] bytes, out RmcpAsfObservation observation,
            ushort sourcePort = 50000, ushort destinationPort = 623,
            bool complete = true, bool managementEndpoint = true)
            => RmcpAsfEnvelopeInspector.TryInspect(bytes, sourcePort,
                destinationPort, complete, managementEndpoint, out observation);

        [Theory]
        [InlineData((byte)0x80)]
        [InlineData((byte)0x40)]
        [InlineData((byte)0x81)]
        [InlineData((byte)0x41)]
        [InlineData((byte)0x82)]
        [InlineData((byte)0x42)]
        [InlineData((byte)0x10)]
        [InlineData((byte)0x11)]
        [InlineData((byte)0x12)]
        [InlineData((byte)0x13)]
        public void PublishedAsfEnvelopeTypesHaveBoundedShape(byte type)
        {
            Assert.True(Inspect(Asf(type), out var found));
            Assert.Equal((byte?)type, found.MessageType);
            Assert.Equal(type is 0x10 or 0x11 or 0x12 or 0x13,
                found.IsPowerControlRequestUnverified);
            Assert.False(found.IsAcknowledge);
        }

        [Fact] public void AcknowledgeIsOnlyFourBytesAndNotAnOutcome()
        {
            Assert.True(Inspect(new byte[] { 6, 0, 1, 0x86 }, out var found));
            Assert.True(found.IsAcknowledge);
            Assert.Null(found.MessageType);
            Assert.False(found.IsPowerControlRequestUnverified);
        }

        [Fact] public void ResponseDirectionMayUseManagementSourcePort()
            => Assert.True(Inspect(Asf(0x40), out _, 623, 51000));

        [Fact] public void MaximumBoundedDataLengthIsAccepted()
        {
            var packet = Asf(0x80, 255);
            Assert.True(Inspect(packet, out var found));
            Assert.Equal(267, found.DatagramLength);
        }

        [Fact] public void WrongPortAndSecureExtensionPortAreNotClaimed()
        {
            Assert.False(Inspect(Asf(), out _, 50000, 50001));
            Assert.False(Inspect(Asf(), out _, 50000, 644));
        }

        [Fact] public void HttpAndTlsCannotMasqueradeAsAsf()
        {
            Assert.False(Inspect(System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1"), out _));
            Assert.False(Inspect(new byte[] { 0x16, 3, 3, 0, 5 }, out _));
        }

        [Fact] public void IpmiClassSevenAndOemClassEightAreNotDecoded()
        {
            var packet = Asf(); packet[3] = 7;
            Assert.False(Inspect(packet, out _));
            packet[3] = 8;
            Assert.False(Inspect(packet, out _));
        }

        [Fact] public void FutureVersionsAndReservedHeaderBitsFail()
        {
            var packet = Asf(); packet[0] = 7;
            Assert.False(Inspect(packet, out _));
            packet = Asf(); packet[1] = 1;
            Assert.False(Inspect(packet, out _));
            packet = Asf(); packet[3] = 0x16;
            Assert.False(Inspect(packet, out _));
        }

        [Fact] public void TruncatedHeaderAndAsfEnvelopeFail()
        {
            Assert.False(Inspect(new byte[] { 6, 0, 1 }, out _));
            Assert.False(Inspect(Asf().Take(11).ToArray(), out _));
        }

        [Fact] public void OverlongPayloadFailsBeforeParsing()
            => Assert.False(Inspect(new byte[268], out _));

        [Fact] public void EnterpriseNumberMustBeAsf()
        {
            var packet = Asf(); packet[7] = 0xbf;
            Assert.False(Inspect(packet, out _));
        }

        [Fact] public void ReservedAsfDataByteMustBeZero()
        {
            var packet = Asf(); packet[10] = 1;
            Assert.False(Inspect(packet, out _));
        }

        [Fact] public void DeclaredDataLengthMustMatchWholeUdpPayload()
        {
            var packet = Asf(0x80, 2); packet[11] = 1;
            Assert.False(Inspect(packet, out _));
            packet[11] = 3;
            Assert.False(Inspect(packet, out _));
        }

        [Fact] public void UnknownAndSecureSessionTypesFailClosed()
        {
            Assert.False(Inspect(Asf(0x01), out _));
            Assert.False(Inspect(Asf(0xc0), out _));
        }

        [Fact] public void AcknowledgeCannotCarryDataOrUseNoAckSequence()
        {
            var packet = Asf(); packet[3] = 0x86;
            Assert.False(Inspect(packet, out _));
            Assert.False(Inspect(new byte[] { 6, 0, 255, 0x86 }, out _));
        }

        [Fact] public void BareFourByteNonAcknowledgeIsIncomplete()
            => Assert.False(Inspect(new byte[] { 6, 0, 1, 6 }, out _));

        [Fact] public void CompleteUdpPayloadProvenanceIsMandatory()
            => Assert.False(Inspect(Asf(), out _, complete: false));

        [Fact] public void ManagementEndpointProvenanceIsMandatory()
            => Assert.False(Inspect(Asf(), out _, managementEndpoint: false));

        [Fact] public void ReorderingAndRetransmissionDoNotCreateState()
        {
            var first = Asf(0x80, sequence: 2, tag: 19);
            var second = Asf(0x80, sequence: 1, tag: 7);
            Assert.True(Inspect(first, out var a));
            Assert.True(Inspect(second, out var b));
            Assert.True(Inspect(first, out var c));
            Assert.Equal(a, b);
            Assert.Equal(a, c);
        }

        [Fact] public async Task ConcurrentCallsRemainDeterministic()
        {
            var packet = Asf();
            var observations = await Task.WhenAll(Enumerable.Range(0, 32)
                .Select(_ => Task.Run(() =>
                {
                    Assert.True(Inspect(packet, out var found));
                    return found;
                })));
            Assert.All(observations, found => Assert.Equal(observations[0], found));
        }

        [Fact] public void MessageTagSequenceAndDataRemainPrivate()
        {
            var a = Asf(0x80, 4, sequence: 2, tag: 11);
            var b = Asf(0x80, 4, sequence: 3, tag: 99);
            a[12] = 0x11; b[12] = 0xaa;
            Assert.True(Inspect(a, out var first));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public void FailedClassificationResetsOutputToDefault()
        {
            Assert.False(Inspect(Asf(0xff), out var found));
            Assert.Equal(default(RmcpAsfObservation), found);
        }
    }
}
