// SPDX-License-Identifier: MIT
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class MqttAnonymousConnectInspectorTests
    {
        private static readonly byte[] Connect = { 0x10, 0x0d, 0, 4, 77, 81, 84, 84, 4, 2, 0, 30, 0, 1, 65 };
        private static readonly byte[] Accepted = { 0x20, 2, 0, 0 };

        [Fact]
        public void CompleteAnonymousExchangeRecordsOnlyBrokerOutcome()
        {
            Assert.True(MqttAnonymousConnectInspector.TryInspect(Connect, Accepted, true, out var result));
            Assert.True(result.BrokerAccepted);
            Assert.Equal((byte)0, result.ReturnCode);
        }

        [Fact]
        public void RejectedBrokerOutcomeIsNotAcceptance()
        {
            Assert.True(MqttAnonymousConnectInspector.TryInspect(Connect, new byte[] { 0x20, 2, 0, 5 }, true, out var result));
            Assert.False(result.BrokerAccepted);
        }

        [Fact]
        public void UntrustedOrIncompleteCaptureFailsClosed()
        {
            Assert.False(MqttAnonymousConnectInspector.TryInspect(Connect, Accepted, false, out _));
            Assert.False(MqttAnonymousConnectInspector.TryInspect(Connect.AsSpan(0, 14), Accepted, true, out _));
        }

        [Fact]
        public void CredentialFlagsAndTrailingBytesCannotMasqueradeAsAnonymous()
        {
            var credentials = (byte[])Connect.Clone();
            credentials[9] = 0x82;
            Assert.False(MqttAnonymousConnectInspector.TryInspect(credentials, Accepted, true, out _));
            Assert.False(MqttAnonymousConnectInspector.TryInspect(new byte[] { 0x10, 0x0e, 0, 4, 77, 81, 84, 84, 4, 2, 0, 30, 0, 1, 65, 66 }, Accepted, true, out _));
        }

        [Fact]
        public void InvalidConnackAndSessionFlagsFailClosed()
        {
            Assert.False(MqttAnonymousConnectInspector.TryInspect(Connect, new byte[] { 0x20, 2, 1, 0 }, true, out _));
            Assert.False(MqttAnonymousConnectInspector.TryInspect(Connect, new byte[] { 0x20, 2, 0, 6 }, true, out _));
        }
    }
}
