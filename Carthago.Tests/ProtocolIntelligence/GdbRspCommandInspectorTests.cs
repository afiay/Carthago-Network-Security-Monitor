// SPDX-License-Identifier: MIT
// Synthetic GNU GDB RSP packets; SOURCE CANDIDATE — UNVERIFIED, 0 EXECUTED.
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class GdbRspCommandInspectorTests
    {
        [Theory]
        [InlineData("qSupported", GdbRspCommandKind.Query)]
        [InlineData("m100,4", GdbRspCommandKind.MemoryRead)]
        [InlineData("M100,1:ff", GdbRspCommandKind.MemoryWrite)]
        [InlineData("p0", GdbRspCommandKind.RegisterRead)]
        [InlineData("P0=ff", GdbRspCommandKind.RegisterWrite)]
        [InlineData("vCont?", GdbRspCommandKind.ExtendedControl)]
        [InlineData("Z0,100,1", GdbRspCommandKind.BreakpointChange)]
        public void ValidClientCommandFamiliesAreOnlyEnvelopeClassified(
            string payload, GdbRspCommandKind expected)
        {
            Assert.True(Inspect(Packet(payload), out var result));
            Assert.Equal(expected, result.CommandKindUnverified);
        }

        [Fact]
        public void RemoteMonitorIsOnlyFlaggedAsPotentiallyStateChanging()
        {
            Assert.True(Inspect(Packet("qRcmd,68656c70"), out var result));
            Assert.Equal(GdbRspCommandKind.RemoteMonitor, result.CommandKindUnverified);
            Assert.True(result.PotentiallyStateChangingUnverified);
        }

        [Fact]
        public void EscapedBinaryPayloadUsesChecksumOfEncodedBytes()
        {
            byte[] data = { (byte)'X', (byte)'0', (byte)',', (byte)'1',
                (byte)':', (byte)'}', 0x03 }; // escaped '#'
            Assert.True(Inspect(Packet(data), out var result));
            Assert.Equal(GdbRspCommandKind.MemoryWrite, result.CommandKindUnverified);
            Assert.True(result.ContainsEscapedBytes);
        }

        [Fact]
        public void UnescapedNestedPacketMarkerFailsClosed()
        {
            Assert.False(Inspect(Packet("q$Supported"), out _));
        }

        [Fact]
        public void UnescapedEmbeddedDelimiterFailsClosed()
        {
            Assert.False(Inspect(Packet("q#Supported"), out _));
        }

        [Fact]
        public void DanglingEscapeFailsClosed()
        {
            Assert.False(Inspect(Packet(new byte[] { (byte)'X', (byte)'}' }), out _));
        }

        [Fact]
        public void UnsupportedEscapeValueFailsClosed()
        {
            Assert.False(Inspect(Packet(new byte[] { (byte)'X', (byte)'}', 0x7f }), out _));
        }

        [Fact]
        public void ChecksumMismatchFailsClosed()
        {
            byte[] packet = Packet("qSupported");
            packet[^1] = packet[^1] == (byte)'0' ? (byte)'1' : (byte)'0';
            Assert.False(Inspect(packet, out _));
        }

        [Fact]
        public void NonHexChecksumFailsClosed()
        {
            byte[] packet = Packet("qSupported");
            packet[^1] = (byte)'g';
            Assert.False(Inspect(packet, out _));
        }

        [Fact]
        public void TruncatedFrameFailsClosed()
        {
            byte[] packet = Packet("qSupported");
            Assert.False(Inspect(packet.AsSpan(0, packet.Length - 1), out _));
        }

        [Fact]
        public void CoalescedPacketsAreNotPretendedToBeOneMessage()
        {
            byte[] packet = Packet("qSupported");
            Assert.False(Inspect(packet.Concat(packet).ToArray(), out _));
        }

        [Fact]
        public void OversizedEncodedPayloadFailsClosed()
        {
            Assert.False(Inspect(Packet(new string('q', 4097)), out _));
        }

        [Fact]
        public void AckAndInterruptAreNotPackets()
        {
            Assert.False(Inspect(new byte[] { (byte)'+' }, out _));
            Assert.False(Inspect(new byte[] { 0x03 }, out _));
        }

        [Fact]
        public void CrossProtocolDataIsNotARecognizedClientCommand()
        {
            Assert.False(Inspect(Packet("HTTP/1.1"), out _));
            Assert.False(Inspect(Packet("GET / HTTP/1.1"), out _));
            Assert.False(Inspect(Packet("X-HTTP"), out _));
            Assert.False(Inspect(Packet("DNSQUERY"), out _));
        }

        [Theory]
        [InlineData(false, true, true, true)]
        [InlineData(true, false, true, true)]
        [InlineData(true, true, false, true)]
        [InlineData(true, true, true, false)]
        public void MissingTrustedBoundaryPlaintextSourceOrDirectionFailsClosed(
            bool boundary, bool plaintext, bool provenance, bool direction)
        {
            Assert.False(GdbRspCommandInspector.TryInspect(
                Packet("qSupported"), boundary, plaintext, provenance, direction, out _));
        }

        [Fact]
        public void NoAcknowledgmentModeStillRequiresValidChecksum()
        {
            byte[] packet = Packet("QStartNoAckMode");
            Assert.True(Inspect(packet, out var result));
            Assert.Equal(GdbRspCommandKind.Configuration, result.CommandKindUnverified);
            packet[^2] = (byte)'g';
            Assert.False(Inspect(packet, out _));
        }

        [Fact]
        public void ObservationDoesNotRetainCommandBytesOrArguments()
        {
            Assert.True(Inspect(Packet("M100,4:deadbeef"), out var result));
            Assert.True(result.PotentiallyStateChangingUnverified);
            Assert.DoesNotContain(typeof(GdbRspCommandObservation).GetProperties(),
                property => property.PropertyType == typeof(string) ||
                            property.PropertyType == typeof(byte[]));
        }

        [Fact]
        public void DuplicateFramesAreStatelessAndDeterministic()
        {
            byte[] packet = Packet("qSupported");
            Assert.True(Inspect(packet, out var first));
            Assert.True(Inspect(packet, out var second));
            Assert.Equal(first, second);
        }

        [Fact]
        public void ConcurrentInspectionDoesNotShareState()
        {
            byte[] packet = Packet("qSupported");
            bool[] outcomes = new bool[64];
            Parallel.For(0, outcomes.Length, i =>
            {
                outcomes[i] = Inspect(packet, out var result) &&
                    result.CommandKindUnverified == GdbRspCommandKind.Query;
            });
            Assert.All(outcomes, value => Assert.True(value));
        }

        private static bool Inspect(ReadOnlySpan<byte> packet, out GdbRspCommandObservation result) =>
            GdbRspCommandInspector.TryInspect(packet, true, true, true, true, out result);

        private static byte[] Packet(string payload) => Packet(Encoding.ASCII.GetBytes(payload));

        private static byte[] Packet(byte[] payload)
        {
            byte[] result = new byte[payload.Length + 4];
            result[0] = (byte)'$';
            payload.CopyTo(result, 1);
            result[payload.Length + 1] = (byte)'#';
            int checksum = 0;
            foreach (byte value in payload)
                checksum = (checksum + value) & 0xff;
            const string hex = "0123456789abcdef";
            result[^2] = (byte)hex[checksum >> 4];
            result[^1] = (byte)hex[checksum & 0xf];
            return result;
        }
    }
}
