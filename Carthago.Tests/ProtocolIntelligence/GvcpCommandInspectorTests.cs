// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic request envelopes; no device, network, credential or actual camera.
    public sealed class GvcpCommandInspectorTests
    {
        private static byte[] Request(ushort command = 0x0002, int payloadLength = 0,
            byte flags = 0x11)
        {
            var bytes = new byte[8 + payloadLength];
            bytes[0] = 0x42;
            bytes[1] = flags;
            bytes[2] = (byte)(command >> 8);
            bytes[3] = (byte)command;
            bytes[4] = (byte)(payloadLength >> 8);
            bytes[5] = (byte)payloadLength;
            bytes[6] = 0x12;
            bytes[7] = 0x34; // Request ID deliberately not retained.
            return bytes;
        }

        private static bool Inspect(byte[] packet, out GvcpCommandObservation observation,
            bool complete = true, bool endpoint = true, bool plaintext = true)
            => GvcpCommandInspector.TryInspect(packet, complete, endpoint, plaintext,
                out observation);

        [Fact] public void DiscoveryRequestHasOnlyShapeMetadata()
        {
            Assert.True(Inspect(Request(), out var found));
            Assert.Equal(GvcpCommandKind.Discovery, found.Command);
            Assert.True(found.IsBroadcastRequestUnverified);
            Assert.False(found.IsPotentialConfigurationAttemptUnverified);
            Assert.Equal(0, found.DeclaredPayloadBytes);
        }

        [Fact] public void ForceIpBroadcastIsOnlyPotentialConfigurationAttempt()
        {
            Assert.True(Inspect(Request(0x0004, 56), out var found));
            Assert.Equal(GvcpCommandKind.ForceIp, found.Command);
            Assert.True(found.IsPotentialConfigurationAttemptUnverified);
        }

        [Fact] public void ReadRegisterRequestIsNotConfiguration()
        {
            Assert.True(Inspect(Request(0x0080, 4, 0x01), out var found));
            Assert.Equal(GvcpCommandKind.ReadRegister, found.Command);
            Assert.False(found.IsPotentialConfigurationAttemptUnverified);
        }

        [Fact] public void WriteRegisterRequestIsOnlyAttempt()
        {
            Assert.True(Inspect(Request(0x0082, 8, 0x01), out var found));
            Assert.Equal(GvcpCommandKind.WriteRegister, found.Command);
            Assert.True(found.IsPotentialConfigurationAttemptUnverified);
        }

        [Fact] public void BoundedMultiRegisterRequestIsRecognizedWithoutValues()
        {
            Assert.True(Inspect(Request(0x0082, 16, 0x01), out var found));
            Assert.Equal(16, found.DeclaredPayloadBytes);
        }

        [Fact] public void CrossProtocolTrafficIsRejected()
        {
            Assert.False(Inspect(System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1"), out _));
            Assert.False(Inspect(new byte[] { 0x00, 0, 0, 3, 0, 0, 0, 1 }, out _));
        }

        [Fact] public void WrongMagicAndUnknownCommandFailClosed()
        {
            var packet = Request();
            packet[0] = 0x43;
            Assert.False(Inspect(packet, out _));
            Assert.False(Inspect(Request(0x7777), out _));
        }

        [Fact] public void UnsupportedFlagsAndAckShapedResponseFailClosed()
        {
            Assert.False(Inspect(Request(flags: 0x00), out _));
            Assert.False(Inspect(Request(flags: 0xFF), out _));
            Assert.False(Inspect(new byte[] { 0, 0, 0, 3, 0, 0, 0x12, 0x34 }, out _));
        }

        [Fact] public void TruncatedHeaderAndDeclaredPayloadFailClosed()
        {
            Assert.False(Inspect(Request().Take(7).ToArray(), out _));
            Assert.False(Inspect(Request(0x0080, 4, 0x01).Take(11).ToArray(), out _));
        }

        [Fact] public void TrailingBytesAndDeclaredLengthMismatchFailClosed()
        {
            Assert.False(Inspect(Request().Concat(new byte[] { 0 }).ToArray(), out _));
            var packet = Request(0x0080, 4, 0x01);
            packet[5] = 3;
            Assert.False(Inspect(packet, out _));
        }

        [Fact] public void CommandSpecificLengthsAreMandatory()
        {
            Assert.False(Inspect(Request(0x0002, 4), out _));
            Assert.False(Inspect(Request(0x0004, 55), out _));
            Assert.False(Inspect(Request(0x0080, 8, 0x01), out _));
            Assert.False(Inspect(Request(0x0082, 7, 0x01), out _));
        }

        [Fact] public void DangerousShapeRequiresAppropriateBroadcastFlag()
        {
            Assert.False(Inspect(Request(0x0004, 56, 0x01), out _));
            Assert.False(Inspect(Request(0x0082, 8, 0x11), out _));
        }

        [Fact] public void AllocationBoundRejectsOversizedDatagrams()
        {
            Assert.False(Inspect(new byte[4097], out _));
            Assert.False(Inspect(Request(0x0082, 1032, 0x01), out _));
            Assert.True(Inspect(Request(0x0082, 1024, 0x01), out _));
        }

        [Fact] public void AllProvenanceAttestationsAreMandatory()
        {
            var packet = Request();
            Assert.False(Inspect(packet, out _, complete: false));
            Assert.False(Inspect(packet, out _, endpoint: false));
            Assert.False(Inspect(packet, out _, plaintext: false));
        }

        [Fact] public void DuplicateAndOutOfOrderPacketsDoNotCreateState()
        {
            var first = Request(0x0080, 4, 0x01);
            var last = Request(0x0082, 8, 0x01);
            Assert.True(Inspect(last, out var a));
            Assert.True(Inspect(first, out _));
            Assert.True(Inspect(last, out var b));
            Assert.Equal(a, b);
        }

        [Fact] public async Task ConcurrentCallsAreDeterministic()
        {
            var packet = Request(0x0004, 56);
            var found = await Task.WhenAll(Enumerable.Range(0, 24).Select(_ =>
                Task.Run(() =>
                {
                    Assert.True(Inspect(packet, out var result));
                    return result;
                })));
            Assert.All(found, item => Assert.Equal(found[0], item));
        }

        [Fact] public void PrivateDeviceFieldsAndRequestIdAreNotExposed()
        {
            var first = Request(0x0004, 56);
            var second = Request(0x0004, 56);
            first[8] = 0x44;
            second[8] = 0x99;
            second[6] = 0xee;
            second[7] = 0xff;
            Assert.True(Inspect(first, out var a));
            Assert.True(Inspect(second, out var b));
            Assert.Equal(a, b);
        }

        [Fact] public void RejectedInputReturnsDefaultObservation()
        {
            Assert.False(Inspect(Request(0x0082, 3, 0x01), out var found));
            Assert.Equal(default(GvcpCommandObservation), found);
        }
    }
}
