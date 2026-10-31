// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 6733 structural envelopes; not captured traffic or authenticated AAA.
    public sealed class DiameterMessageInspectorTests
    {
        private static void Write24(Span<byte> target, int value)
        {
            target[0] = (byte)(value >> 16);
            target[1] = (byte)(value >> 8);
            target[2] = (byte)value;
        }

        private static byte[] Avp(uint code, byte flags, byte[] value, uint vendorId = 0)
        {
            int headerLength = (flags & 0x80) != 0 ? 12 : 8;
            int length = headerLength + value.Length;
            var bytes = new byte[(length + 3) & ~3];
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(0, 4), code);
            bytes[4] = flags;
            Write24(bytes.AsSpan(5, 3), length);
            if (headerLength == 12)
                BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8, 4), vendorId);
            value.CopyTo(bytes, headerLength);
            return bytes;
        }

        private static byte[] Message(byte flags = 0x80, int command = 257,
            uint application = 0, params byte[][] attributes)
        {
            int length = 20;
            foreach (var attribute in attributes)
                length += attribute.Length;
            var bytes = new byte[length];
            bytes[0] = 1;
            Write24(bytes.AsSpan(1, 3), length);
            bytes[4] = flags;
            Write24(bytes.AsSpan(5, 3), command);
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8, 4), application);
            // Synthetic correlation identifiers intentionally never leave the inspector.
            bytes[12] = 0x12; bytes[16] = 0x34;
            int cursor = 20;
            foreach (var attribute in attributes)
            {
                attribute.CopyTo(bytes, cursor);
                cursor += attribute.Length;
            }
            return bytes;
        }

        private static bool Inspect(byte[] bytes, out DiameterObservation result,
            bool attested = true, DiameterTransport transport = DiameterTransport.Tcp)
            => DiameterMessageInspector.TryInspect(bytes, transport, attested, out result);

        // Valid structural envelopes and typed, non-sensitive metadata.
        [Theory]
        [InlineData(257)]
        [InlineData(258)]
        [InlineData(280)]
        [InlineData(282)]
        public void BaseCommandsAreStructurallyRecognized(int command)
        {
            Assert.True(Inspect(Message(command: command), out var found));
            Assert.Equal(command, found.CommandCode);
            Assert.True(found.IsRequest);
        }

        [Fact] public void CapabilityRequestWithPaddedAvpsIsRecognized()
        {
            var message = Message(attributes: new[]
            {
                Avp(264, 0x40, Encoding.ASCII.GetBytes("node.example")),
                Avp(296, 0x40, Encoding.ASCII.GetBytes("example")),
                Avp(257, 0x40, new byte[] { 0, 1, 192, 0, 2, 5 }),
                Avp(266, 0x40, new byte[] { 0, 0, 0, 9 }),
                Avp(269, 0, Encoding.ASCII.GetBytes("synthetic"))
            });
            Assert.True(Inspect(message, out var found));
            Assert.Equal(5, found.AvpCount);
            Assert.Equal(message.Length, found.MessageLength);
        }

        [Fact] public void AnswerAndErrorAreNotAuthorizationOutcomes()
        {
            Assert.True(Inspect(Message(flags: 0x20), out var found));
            Assert.False(found.IsRequest);
            Assert.True(found.IsError);
        }

        [Fact] public void RequestRetransmissionFlagIsOnlyAHeaderHint()
        {
            Assert.True(Inspect(Message(flags: 0x90), out var found));
            Assert.True(found.PotentialRetransmission);
        }

        [Fact] public void ApplicationIdIsExposedWithoutSessionIdentity()
        {
            Assert.True(Inspect(Message(application: 16777216), out var found));
            Assert.Equal(16777216u, found.ApplicationId);
        }

        [Fact] public void VendorAvpIsCountedButVendorIdentityIsNotRetained()
        {
            Assert.True(Inspect(Message(attributes: new[] { Avp(1, 0x80, Array.Empty<byte>(), 10415) }),
                out var found));
            Assert.True(found.HasVendorSpecificAvp);
            Assert.Equal(1, found.AvpCount);
        }

        // Legitimate negatives and cross-protocol discrimination.
        [Fact] public void TlsAndHttpHeadersAreNotDiameter()
        {
            Assert.False(Inspect(new byte[] { 0x16, 3, 3, 0, 40 }, out _));
            Assert.False(Inspect(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n"), out _));
        }

        [Fact] public void UnsupportedTransportDoesNotCreateAProtocolClaim()
        {
            Assert.False(Inspect(Message(), out _, transport: DiameterTransport.Unknown));
        }

        [Fact] public void VersionAndCommandCodeMustBeRecognizable()
        {
            var message = Message(); message[0] = 2;
            Assert.False(Inspect(message, out _));
            message = Message(); message[5] = 0; message[6] = 0; message[7] = 0;
            Assert.False(Inspect(message, out _));
        }

        // Malformed, truncated, overlong, reserved, spoofed and padding controls.
        [Fact] public void TruncatedAndOverlongMessagesFailClosed()
        {
            Assert.False(Inspect(new byte[19], out _));
            Assert.False(Inspect(new byte[16388], out _));
            var truncated = Message(); Array.Resize(ref truncated, 19);
            Assert.False(Inspect(truncated, out _));
        }

        [Fact] public void DeclaredLengthAndAlignmentMustMatchExactBoundary()
        {
            var data = Message(); data[3] = 24;
            Assert.False(Inspect(data, out _));
            data = Message(); data[3] = 21;
            Assert.False(Inspect(data, out _));
            data = Message(); Array.Resize(ref data, 24);
            Assert.False(Inspect(data, out _));
        }

        [Fact] public void ReservedFlagsAndRequestErrorCombinationFail()
        {
            Assert.False(Inspect(Message(flags: 0x81), out _));
            Assert.False(Inspect(Message(flags: 0xa0), out _));
            Assert.False(Inspect(Message(flags: 0x10), out _));
        }

        [Fact] public void AvpLengthCannotUnderrunOrOverrunHeader()
        {
            var data = Message(attributes: new[] { Avp(264, 0x40, Array.Empty<byte>()) });
            data[27] = 7;
            Assert.False(Inspect(data, out _));
            data = Message(attributes: new[] { Avp(264, 0x40, Array.Empty<byte>()) });
            data[27] = 30;
            Assert.False(Inspect(data, out _));
        }

        [Fact] public void VendorFlagRequiresNonzeroVendorIdAndFullHeader()
        {
            Assert.False(Inspect(Message(attributes: new[] { Avp(1, 0x80, Array.Empty<byte>()) }), out _));
            var data = Message(attributes: new[] { Avp(1, 0x80, Array.Empty<byte>(), 99) });
            data[27] = 8;
            Assert.False(Inspect(data, out _));
        }

        [Fact] public void NonzeroAvpPaddingAndReservedAvpFlagsFail()
        {
            var data = Message(attributes: new[] { Avp(264, 0x40, new byte[] { 1 }) });
            data[data.Length - 1] = 9;
            Assert.False(Inspect(data, out _));
            Assert.False(Inspect(Message(attributes: new[] { Avp(264, 0x01, Array.Empty<byte>()) }), out _));
        }

        [Fact] public void AvpCountIsFinite()
        {
            var attrs = new byte[257][];
            for (int i = 0; i < attrs.Length; i++)
                attrs[i] = Avp(264, 0, Array.Empty<byte>());
            Assert.False(Inspect(Message(attributes: attrs), out _));
        }

        // Stateless duplicate, ordering and concurrent observations.
        [Fact] public void DuplicateAndOutOfOrderEnvelopesHaveNoSharedState()
        {
            var request = Message(flags: 0x80);
            var answer = Message(flags: 0);
            Assert.True(Inspect(answer, out var first));
            Assert.True(Inspect(request, out _));
            Assert.True(Inspect(answer, out var again));
            Assert.Equal(first, again);
        }

        [Fact] public void ConcurrentCallsAreDeterministic()
        {
            var message = Message(attributes: new[] { Avp(264, 0x40, new byte[] { 1 }) });
            int matches = 0;
            Parallel.For(0, 64, _ =>
            {
                if (Inspect(message, out var result) && result.AvpCount == 1)
                    Interlocked.Increment(ref matches);
            });
            Assert.Equal(64, matches);
        }

        // Provenance, privacy and opaque/encrypted fail-closed boundary.
        [Fact] public void UnattestedPlaintextBoundaryIsRejected()
        {
            Assert.False(Inspect(Message(), out var found, attested: false));
            Assert.Equal(default(DiameterObservation), found);
        }

        [Fact] public void SctpRequiresExternalCompleteMessageProducer()
        {
            Assert.True(Inspect(Message(), out _, transport: DiameterTransport.Sctp));
            Assert.False(Inspect(Message(), out _, attested: false, transport: DiameterTransport.Sctp));
        }

        [Fact] public void AvpValuesAndCorrelationIdentifiersAreNotReturned()
        {
            var data = Message(attributes: new[] { Avp(264, 0x40, Encoding.ASCII.GetBytes("SECRET")) });
            Assert.True(Inspect(data, out var found));
            Assert.Equal(8, typeof(DiameterObservation).GetProperties().Length);
            Assert.DoesNotContain("SECRET", found.ToString());
            Assert.DoesNotContain("0x12", found.ToString());
        }

        [Fact] public void FailedInspectionResetsOutObservation()
        {
            Assert.True(Inspect(Message(), out _));
            Assert.False(Inspect(new byte[0], out var found));
            Assert.Equal(default(DiameterObservation), found);
        }
    }
}
