// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic MQTT-SN v1.2 datagrams based on mqtt.org specification; not captures.
    public sealed class MqttSnDatagramInspectorTests
    {
        private static byte[] Frame(byte type, params byte[] body)
        {
            var bytes = new byte[body.Length + 2];
            bytes[0] = (byte)bytes.Length; bytes[1] = type;
            Array.Copy(body, 0, bytes, 2, body.Length);
            return bytes;
        }
        private static bool Inspect(byte[] bytes, out MqttSnObservation result, bool complete = true)
            => MqttSnDatagramInspector.TryInspect(bytes, complete, out result);

        // Positive: selected message shapes, not complete MQTT-SN coverage.
        [Fact] public void AdvertiseAndSearchGatewayAreBounded()
        {
            Assert.True(Inspect(Frame(0x00, 1, 0, 30), out var a));
            Assert.Equal(MqttSnMessageKind.Advertise, a.Kind);
            Assert.True(Inspect(Frame(0x01, 2), out var s));
            Assert.Equal(MqttSnMessageKind.SearchGateway, s.Kind);
            Assert.True(Inspect(Frame(0x02, 1), out var g));
            Assert.Equal(MqttSnMessageKind.GatewayInfo, g.Kind);
        }
        [Fact] public void ConnectFlagsAreTypedWithoutClientIdentity()
        {
            Assert.True(Inspect(Frame(0x04, 0x0c, 1, 0, 30, 0x41, 0x42), out var r));
            Assert.Equal(MqttSnMessageKind.Connect, r.Kind);
            Assert.True(r.CleanSession);
            Assert.True(r.WillRequested);
            Assert.Null(r.Retain);
        }
        [Fact] public void PublishRetainAndQosAreOnlyHeaderMetadata()
        {
            Assert.True(Inspect(Frame(0x0c, 0x50, 0x12, 0x34, 0, 1, 0xff), out var r));
            Assert.Equal(MqttSnMessageKind.Publish, r.Kind);
            Assert.True(r.Retain);
            Assert.Equal((byte)2, r.Qos);
        }
        [Fact] public void CanonicalExtendedLengthMessageIsAccepted()
        {
            var bytes = new byte[256];
            bytes[0] = 1; bytes[1] = 1; bytes[2] = 0; bytes[3] = 0x0c;
            Assert.True(Inspect(bytes, out var r));
            Assert.Equal(256, r.MessageLength);
        }
        [Theory]
        [InlineData((byte)0x16, MqttSnMessageKind.PingRequest)]
        [InlineData((byte)0x17, MqttSnMessageKind.PingResponse)]
        [InlineData((byte)0x18, MqttSnMessageKind.Disconnect)]
        public void EmptyControlMessagesHaveRecognizedShape(byte type, MqttSnMessageKind kind)
        {
            Assert.True(Inspect(Frame(type), out var r));
            Assert.Equal(kind, r.Kind);
        }

        // Legitimate negatives and cross-protocol discriminators.
        [Fact] public void OrdinaryMqttAndRtpAreNotMqttSn()
        {
            Assert.False(Inspect(new byte[] { 0x10, 0x00 }, out _));
            Assert.False(Inspect(new byte[] { 0x80, 0x60, 0, 1, 0, 0 }, out _));
        }
        [Fact] public void ReservedAndUnsupportedTypesFailClosed()
        {
            Assert.False(Inspect(Frame(0x03), out _));
            Assert.False(Inspect(Frame(0xfe, 0, 0, 0), out _));
            Assert.False(Inspect(Frame(0x12, 0, 0, 0), out _));
        }
        [Fact] public void WrongBodyShapeAndProtocolVersionFail()
        {
            Assert.False(Inspect(Frame(0x00, 1), out _));
            Assert.False(Inspect(Frame(0x04, 0, 2, 0, 30), out _));
            Assert.False(Inspect(Frame(0x18, 0), out _));
        }

        // Malformed, truncated, overlong and spoofed.
        [Fact] public void HeaderLengthAndCanonicalEncodingMustAgree()
        {
            Assert.False(Inspect(new byte[] { 1, 0 }, out _));
            Assert.False(Inspect(new byte[] { 1, 0, 5 }, out _));
            Assert.False(Inspect(new byte[] { 1, 0, 5, 0x17, 0 }, out _));
            Assert.False(Inspect(new byte[] { 4, 0x17 }, out _));
        }
        [Fact] public void InvalidFlagsAndReturnCodesFail()
        {
            Assert.False(Inspect(Frame(0x04, 0x80, 1, 0, 30), out _));
            Assert.False(Inspect(Frame(0x0c, 3, 0, 1, 0, 1), out _));
            Assert.False(Inspect(Frame(0x05, 4), out _));
        }
        [Fact] public void OversizeAndTruncatedLongFrameFail()
        {
            Assert.False(Inspect(new byte[4097], out _));
            var bytes = new byte[256];
            bytes[0] = 1; bytes[1] = 1; bytes[2] = 0; bytes[3] = 0x0c;
            Array.Resize(ref bytes, 255);
            Assert.False(Inspect(bytes, out _));
        }

        // Stateless duplicates, reordering and concurrency.
        [Fact] public void DuplicateAndReorderedMessagesAreIndependent()
        {
            var a = Frame(0x00, 1, 0, 30);
            Assert.True(Inspect(a, out var first));
            Assert.True(Inspect(Frame(0x17), out _));
            Assert.True(Inspect(a, out var repeated));
            Assert.Equal(first, repeated);
        }
        [Fact] public void ConcurrentInspectionDoesNotShareState()
        {
            var a = Frame(0x0c, 0, 0, 1, 0, 1);
            int hits = 0;
            Parallel.For(0, 64, _ =>
            {
                if (Inspect(a, out var r) && r.Kind == MqttSnMessageKind.Publish)
                    Interlocked.Increment(ref hits);
            });
            Assert.Equal(64, hits);
        }

        // Provenance, opaque transport, privacy and fail-closed output.
        [Fact] public void UnattestedOrEncryptedPayloadFails()
        {
            Assert.False(Inspect(Frame(0x17), out var r, complete: false));
            Assert.Equal(default(MqttSnObservation), r);
            Assert.False(Inspect(new byte[] { 0x17, 0x03, 0x03, 0x00 }, out _));
        }
        [Fact] public void ClientIdTopicAndMessageBytesAreNeverReturned()
        {
            var b = Frame(0x04, 0x04, 1, 0, 1, 0x53, 0x45, 0x43);
            Assert.True(Inspect(b, out var r));
            Assert.Equal(6, typeof(MqttSnObservation).GetProperties().Length);
            Assert.DoesNotContain("SEC", r.ToString());
        }
        [Fact] public void FailedInspectionCannotReusePreviousObservation()
        {
            Assert.True(Inspect(Frame(0x17), out _));
            Assert.False(Inspect(new byte[] { 0, 0 }, out var r));
            Assert.Equal(default(MqttSnObservation), r);
        }
    }
}
