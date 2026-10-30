// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class Http2FrameInspectorTests
    {
        private static byte[] Frame(byte type, byte flags, int streamId, byte[] payload)
        {
            var result = new byte[9 + payload.Length];
            result[0] = (byte)(payload.Length >> 16);
            result[1] = (byte)(payload.Length >> 8);
            result[2] = (byte)payload.Length;
            result[3] = type;
            result[4] = flags;
            result[5] = (byte)(streamId >> 24);
            result[6] = (byte)(streamId >> 16);
            result[7] = (byte)(streamId >> 8);
            result[8] = (byte)streamId;
            payload.CopyTo(result, 9);
            return result;
        }

        [Fact]
        public void VerifiedClientPrefaceAndSettingsAreRecognized()
        {
            var preface = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            var bytes = preface.Concat(Frame(4, 0, 0, Array.Empty<byte>())).ToArray();
            Assert.True(Http2FrameInspector.TryInspect(bytes, true, true, out var observation));
            Assert.True(observation.ClientPrefaceObserved);
            Assert.Equal(4, observation.FrameType);
            Assert.Equal(33, observation.BytesConsumed);
        }

        [Fact]
        public void LegitimateHttp1RequestDoesNotClassifyAsHttp2()
        {
            var bytes = Encoding.ASCII.GetBytes("GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n");
            Assert.False(Http2FrameInspector.TryInspect(bytes, true, true, out _));
        }

        [Fact]
        public void TruncatedFrameFailsClosed()
        {
            var bytes = Frame(6, 0, 0, new byte[8]);
            Assert.False(Http2FrameInspector.TryInspect(bytes.AsSpan(0, bytes.Length - 1), true, false, out _));
        }

        [Fact]
        public void OverlongFrameIsRejectedBeforePayloadInspection()
        {
            Assert.False(Http2FrameInspector.TryInspect(Frame(0, 0, 1, new byte[16_385]), true, false, out _));
        }

        [Fact]
        public void PortOrAlpnHintWithoutTrustedPlaintextContextCannotClassify()
        {
            Assert.False(Http2FrameInspector.TryInspect(Frame(4, 0, 0, Array.Empty<byte>()), false, false, out _));
            Assert.False(Http2FrameInspector.TryInspect(new byte[] { 0x17, 0x03, 0x03, 0, 4, 1, 2, 3, 4 }, false, false, out _));
        }

        [Fact]
        public void VerifiedFrameBoundaryReportsOnlyFirstCoalescedFrame()
        {
            var bytes = Frame(6, 0, 0, new byte[8]).Concat(Frame(4, 1, 0, Array.Empty<byte>())).ToArray();
            Assert.True(Http2FrameInspector.TryInspect(bytes, true, false, out var observation));
            Assert.Equal(17, observation.BytesConsumed);
            Assert.Equal(6, observation.FrameType);
        }

        [Theory]
        [InlineData(6, 0, 0)]
        [InlineData(3, 0, 4)]
        [InlineData(4, 1, 6)]
        public void InvalidFrameShapeIsRejected(byte type, byte flags, int length)
        {
            Assert.False(Http2FrameInspector.TryInspect(Frame(type, flags, 0, new byte[length]), true, false, out _));
        }

        [Fact]
        public void ReservedStreamBitFailsClosed()
        {
            var bytes = Frame(1, 0, 1, Array.Empty<byte>());
            bytes[5] |= 0x80;
            Assert.False(Http2FrameInspector.TryInspect(bytes, true, false, out _));
        }
    }
}
