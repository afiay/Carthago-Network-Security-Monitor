// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Hand-authored RFC 4511 BER envelope fixtures; no captured private traffic.
    public sealed class LdapMessageInspectorTests
    {
        private static byte[] Envelope(byte[] id, byte[] operation, byte[]? controls = null)
        {
            var body = id.Concat(operation).Concat(controls ?? Array.Empty<byte>()).ToArray();
            if (body.Length > 127)
                throw new ArgumentOutOfRangeException(nameof(operation));
            return new byte[] { 0x30, (byte)body.Length }.Concat(body).ToArray();
        }

        private static byte[] Message(int id, byte[] operation)
            => Envelope(new byte[] { 0x02, 0x01, (byte)id }, operation);

        private static readonly byte[] BindRequest =
            { 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00 };

        private static byte[] SimpleBind(byte[] name, byte[] secret, byte version = 3,
            byte authenticationTag = 0x80)
        {
            var value = new byte[] { 0x02, 0x01, version, 0x04, (byte)name.Length }
                .Concat(name)
                .Concat(new byte[] { authenticationTag, (byte)secret.Length })
                .Concat(secret).ToArray();
            return Message(7, new byte[] { 0x60, (byte)value.Length }.Concat(value).ToArray());
        }

        [Fact]
        public void NonemptySimpleBindReportsOnlyMessageShapeNotCredentials()
        {
            var raw = SimpleBind(Encoding.ASCII.GetBytes("cn=user"), Encoding.ASCII.GetBytes("private123"));
            Assert.True(LdapMessageInspector.TryInspectSimpleBind(raw, true, out var found));
            Assert.Equal(7, found.MessageId);
            Assert.Equal(raw.Length, found.BytesConsumed);
            Assert.True(found.HasNonEmptyCredential);
            Assert.DoesNotContain("private123", found.ToString());
            Assert.DoesNotContain("cn=user", found.ToString());
        }

        [Fact]
        public void AnonymousSaslAndUnsupportedVersionDoNotAssertCleartextSimpleBind()
        {
            Assert.False(LdapMessageInspector.TryInspectSimpleBind(SimpleBind(Array.Empty<byte>(), Array.Empty<byte>()), true, out _));
            Assert.False(LdapMessageInspector.TryInspectSimpleBind(SimpleBind(Array.Empty<byte>(), new byte[] { 0x31 }), true, out _));
            Assert.False(LdapMessageInspector.TryInspectSimpleBind(SimpleBind(new byte[] { 0x61 }, Array.Empty<byte>()), true, out _));
            Assert.False(LdapMessageInspector.TryInspectSimpleBind(SimpleBind(new byte[] { 0x61 }, new byte[] { 0x31 }, 2), true, out _));
            Assert.False(LdapMessageInspector.TryInspectSimpleBind(SimpleBind(new byte[] { 0x61 }, new byte[] { 0x31 }, 3, 0xA3), true, out _));
        }

        [Fact]
        public void AmbiguousCoalescedTruncatedControlAndUnauthenticatedBindFailClosed()
        {
            var raw = SimpleBind(new byte[] { 0x61 }, new byte[] { 0x31 });
            Assert.False(LdapMessageInspector.TryInspectSimpleBind(raw, false, out _));
            Assert.False(LdapMessageInspector.TryInspectSimpleBind(raw.AsSpan(0, raw.Length - 1), true, out _));
            Assert.False(LdapMessageInspector.TryInspectSimpleBind(raw.Concat(raw).ToArray(), true, out _));
            Assert.False(LdapMessageInspector.TryInspectSimpleBind(
                Envelope(new byte[] { 0x02, 0x01, 0x07 }, raw.AsSpan(5, raw.Length - 5).ToArray(), new byte[] { 0xA0, 0x00 }),
                true, out _));
        }

        [Fact]
        public void VerifiedPlaintextBindEnvelopeReportsOnlyNonSecretShape()
        {
            var bytes = Message(1, BindRequest);
            Assert.True(LdapMessageInspector.TryInspect(bytes, true, out var found));
            Assert.Equal(1, found.MessageId);
            Assert.Equal((byte)0x60, found.OperationTag);
            Assert.Equal(bytes.Length, found.BytesConsumed);
            Assert.False(found.HasControls);
        }

        [Fact]
        public void LdapPortOrAlpnWithoutTrustedPlaintextBoundaryIsInsufficient()
        {
            Assert.False(LdapMessageInspector.TryInspect(Message(1, BindRequest), false, out _));
            Assert.False(LdapMessageInspector.TryInspect(new byte[] { 0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3 }, false, out _));
        }

        [Fact]
        public void BenignHttpRequestIsNotAnLdapMessage()
        {
            Assert.False(LdapMessageInspector.TryInspect(
                Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n\r\n"), true, out _));
        }

        [Fact]
        public void TruncatedEnvelopeFailsClosed()
        {
            var bytes = Message(1, BindRequest);
            Assert.False(LdapMessageInspector.TryInspect(bytes.AsSpan(0, bytes.Length - 1), true, out _));
        }

        [Theory]
        [InlineData(0x80)]
        [InlineData(0x81)]
        public void IndefiniteOrTruncatedLongFormLengthIsRejected(byte lengthOctet)
        {
            Assert.False(LdapMessageInspector.TryInspect(
                new byte[] { 0x30, lengthOctet, 0x02, 0x01, 0x01, 0x42, 0x00 }, true, out _));
        }

        [Fact]
        public void NegativeAndNonMinimalMessageIdsAreRejected()
        {
            Assert.False(LdapMessageInspector.TryInspect(
                Envelope(new byte[] { 0x02, 0x01, 0xFF }, new byte[] { 0x42, 0x00 }), true, out _));
            Assert.False(LdapMessageInspector.TryInspect(
                Envelope(new byte[] { 0x02, 0x02, 0x00, 0x01 }, new byte[] { 0x42, 0x00 }), true, out _));
        }

        [Fact]
        public void UnknownOperationTagIsNotAnLdapClassification()
        {
            Assert.False(LdapMessageInspector.TryInspect(
                Message(1, new byte[] { 0x7F, 0x01, 0x00 }), true, out _));
        }

        [Fact]
        public void OptionalControlsAndCoalescedMessageAreBoundedToFirstEnvelope()
        {
            var first = Envelope(new byte[] { 0x02, 0x01, 0x01 },
                new byte[] { 0x42, 0x00 }, new byte[] { 0xA0, 0x00 });
            var bytes = first.Concat(Message(2, new byte[] { 0x42, 0x00 })).ToArray();
            Assert.True(LdapMessageInspector.TryInspect(bytes, true, out var found));
            Assert.Equal(first.Length, found.BytesConsumed);
            Assert.True(found.HasControls);
        }

        [Fact]
        public void UnsolicitedZeroMessageIdRequiresExtendedResponseTag()
        {
            Assert.False(LdapMessageInspector.TryInspect(
                Message(0, new byte[] { 0x42, 0x00 }), true, out _));
            var unsolicited = Message(0,
                new byte[] { 0x78, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00 });
            Assert.True(LdapMessageInspector.TryInspect(unsolicited, true, out var found));
            Assert.Equal(0, found.MessageId);
        }

        [Fact]
        public void RepeatedMessageIdsDoNotClaimReplayOrAuthenticationSuccess()
        {
            var bytes = Message(7, new byte[] { 0x42, 0x00 });
            Assert.True(LdapMessageInspector.TryInspect(bytes, true, out var first));
            Assert.True(LdapMessageInspector.TryInspect(bytes, true, out var repeated));
            Assert.Equal(first, repeated);
        }

        [Fact]
        public void OversizedInputFailsBeforeParsingOrAllocating()
        {
            Assert.False(LdapMessageInspector.TryInspect(new byte[65_540], true, out _));
        }
    }
}
