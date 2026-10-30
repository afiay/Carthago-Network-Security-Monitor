// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic public-spec AMQP connection prefaces; not a broker session.
    public sealed class AmqpConnectionHeaderInspectorTests
    {
        private static byte[] Header(byte protocolId, byte major, byte minor, byte revision)
            => new byte[] { 65, 77, 81, 80, protocolId, major, minor, revision };

        [Theory]
        [InlineData(0, 0, 9, 1, AmqpHeaderKind.Amqp091)]
        [InlineData(0, 1, 0, 0, AmqpHeaderKind.Amqp10)]
        [InlineData(3, 1, 0, 0, AmqpHeaderKind.Amqp10Sasl)]
        public void ExactProtocolPrefacesAreDistinguished(
            byte protocolId, byte major, byte minor, byte revision, AmqpHeaderKind expected)
        {
            Assert.True(AmqpConnectionHeaderInspector.TryInspect(
                Header(protocolId, major, minor, revision), true, out var found));
            Assert.Equal(expected, found.Kind);
            Assert.Equal(8, found.BytesConsumed);
        }

        [Fact]
        public void OrdinaryHttpRequestIsNotAmqp()
        {
            Assert.False(AmqpConnectionHeaderInspector.TryInspect(
                Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n"), true, out _));
        }

        [Fact]
        public void TlsCiphertextCannotBecomeAmqpWithoutTrustedBoundary()
        {
            Assert.False(AmqpConnectionHeaderInspector.TryInspect(
                Header(0, 0, 9, 1), false, out _));
            Assert.False(AmqpConnectionHeaderInspector.TryInspect(
                new byte[] { 0x16, 3, 3, 0, 5, 1, 2, 3 }, false, out _));
        }

        [Fact]
        public void TruncatedHeaderFailsClosed()
        {
            var bytes = Header(0, 0, 9, 1);
            Assert.False(AmqpConnectionHeaderInspector.TryInspect(
                bytes.AsSpan(0, bytes.Length - 1), true, out _));
        }

        [Fact]
        public void WrongMagicAndLowercaseMagicAreRejected()
        {
            var bytes = Header(0, 0, 9, 1);
            bytes[0] = (byte)'X';
            Assert.False(AmqpConnectionHeaderInspector.TryInspect(bytes, true, out _));
            bytes[0] = (byte)'a';
            Assert.False(AmqpConnectionHeaderInspector.TryInspect(bytes, true, out _));
        }

        [Fact]
        public void UnknownVersionAndProtocolIdsAreNotGuessed()
        {
            Assert.False(AmqpConnectionHeaderInspector.TryInspect(
                Header(0, 0, 9, 2), true, out _));
            Assert.False(AmqpConnectionHeaderInspector.TryInspect(
                Header(2, 1, 0, 0), true, out _));
        }

        [Fact]
        public void OverlongInputIsRejectedBeforeInspection()
        {
            Assert.False(AmqpConnectionHeaderInspector.TryInspect(
                new byte[4_097], true, out _));
        }

        [Fact]
        public void CoalescedFrameBytesDoNotBecomeAuthenticatedSession()
        {
            var first = Header(0, 0, 9, 1);
            var combined = first.Concat(new byte[] { 1, 0, 0, 0, 0, 0, 0 }).ToArray();
            Assert.True(AmqpConnectionHeaderInspector.TryInspect(combined, true, out var found));
            Assert.Equal(first.Length, found.BytesConsumed);
            Assert.Equal(AmqpHeaderKind.Amqp091, found.Kind);
        }

        [Fact]
        public void RepeatedPrefaceDoesNotClaimBrokerAcceptanceOrReplay()
        {
            var bytes = Header(0, 1, 0, 0);
            Assert.True(AmqpConnectionHeaderInspector.TryInspect(bytes, true, out var first));
            Assert.True(AmqpConnectionHeaderInspector.TryInspect(bytes, true, out var repeated));
            Assert.Equal(first, repeated);
        }

        [Fact]
        public void Amqp10SaslPrefaceDoesNotRevealAuthenticationResult()
        {
            Assert.True(AmqpConnectionHeaderInspector.TryInspect(
                Header(3, 1, 0, 0), true, out var found));
            Assert.Equal(AmqpHeaderKind.Amqp10Sasl, found.Kind);
            Assert.DoesNotContain("Authenticated", found.ToString());
        }
    }
}
