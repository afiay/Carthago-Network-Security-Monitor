// SPDX-License-Identifier: MIT
using System;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 854 control tokens. No real terminal payloads or credentials.
    public sealed class TelnetControlInspectorTests
    {
        [Theory]
        [InlineData((byte)251, TelnetControlKind.Will)]
        [InlineData((byte)252, TelnetControlKind.Wont)]
        [InlineData((byte)253, TelnetControlKind.Do)]
        [InlineData((byte)254, TelnetControlKind.Dont)]
        public void ValidNegotiationToken(byte command, TelnetControlKind kind)
        {
            Assert.True(TelnetControlInspector.TryInspect(
                new byte[] { 255, command, 1 }, true, out var found));
            Assert.Equal(kind, found.Kind);
            Assert.Equal((byte)1, found.Option);
        }

        [Fact] public void ValidSubnegotiationRecognizedWithoutRetainingData()
        {
            byte[] data = { 255, 250, 24, 0x61, 0x62, 255, 240 };
            Assert.True(TelnetControlInspector.TryInspect(data, true, out var found));
            Assert.Equal(TelnetControlKind.Subnegotiation, found.Kind);
            Assert.DoesNotContain("97", found.ToString());
        }

        [Fact] public void EscapedIacInsideSubnegotiationIsNotTerminator()
        {
            byte[] data = { 255, 250, 24, 255, 255, 0x41, 255, 240 };
            Assert.True(TelnetControlInspector.TryInspect(data, true, out _));
        }

        [Fact] public void PlaintextTerminalDataIsNotMisclassified()
        {
            Assert.False(TelnetControlInspector.TryInspect(
                new byte[] { 0x55, 0x53, 0x45, 0x52 }, true, out _));
        }

        [Fact] public void CrossProtocolBytesRejected()
        {
            Assert.False(TelnetControlInspector.TryInspect(
                new byte[] { 0x16, 0x03, 0x03 }, true, out _));
        }

        [Fact] public void UnattestedTcpBoundaryRejected()
        {
            Assert.False(TelnetControlInspector.TryInspect(
                new byte[] { 255, 251, 1 }, false, out _));
        }

        [Fact] public void TruncatedNegotiationRejected()
        {
            Assert.False(TelnetControlInspector.TryInspect(new byte[] { 255, 251 }, true, out _));
        }

        [Fact] public void TrailingBytesAfterNegotiationRejected()
        {
            Assert.False(TelnetControlInspector.TryInspect(
                new byte[] { 255, 251, 1, 0 }, true, out _));
        }

        [Fact] public void UnclosedSubnegotiationRejected()
        {
            Assert.False(TelnetControlInspector.TryInspect(
                new byte[] { 255, 250, 24, 0x41, 255 }, true, out _));
        }

        [Fact] public void NestedUnexpectedIacCommandRejected()
        {
            Assert.False(TelnetControlInspector.TryInspect(
                new byte[] { 255, 250, 24, 255, 251, 0, 255, 240 }, true, out _));
        }

        [Fact] public void OverlongSubnegotiationRejected()
        {
            var bytes = new byte[513]; bytes[0] = 255; bytes[1] = 250;
            bytes[2] = 24; bytes[511] = 255; bytes[512] = 240;
            Assert.False(TelnetControlInspector.TryInspect(bytes, true, out _));
        }

        [Fact] public void RepeatedControlTokenIsDeterministicNotSessionProof()
        {
            byte[] bytes = { 255, 253, 3 };
            Assert.True(TelnetControlInspector.TryInspect(bytes, true, out var first));
            Assert.True(TelnetControlInspector.TryInspect(bytes, true, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public void SensitiveSubnegotiationContentsNeverAppearInObservation()
        {
            byte[] bytes = { 255, 250, 24, 0x41, 0x42, 0x43, 255, 240 };
            Assert.True(TelnetControlInspector.TryInspect(bytes, true, out var found));
            Assert.Equal(8, found.FrameLength);
            Assert.DoesNotContain("ABC", found.ToString());
        }
    }
}
