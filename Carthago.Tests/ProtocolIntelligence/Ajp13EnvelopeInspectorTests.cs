// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic AJP/1.3 envelopes; no Tomcat requests, secrets or outcomes.
    public sealed class Ajp13EnvelopeInspectorTests
    {
        private static byte[] Packet(bool proxyToContainer = true,
            byte code = 0x0A, int payloadLength = 1)
        {
            var data = new byte[4 + payloadLength];
            BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(0, 2),
                proxyToContainer ? (ushort)0x1234 : (ushort)0x4142);
            BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(2, 2), (ushort)payloadLength);
            data[4] = code;
            return data;
        }

        private static bool Inspect(byte[] data, out Ajp13EnvelopeObservation found,
            bool complete = true, bool endpoint = true)
            => Ajp13EnvelopeInspector.TryInspect(data, complete, endpoint, out found);

        [Theory]
        [InlineData(0x02, 3)]
        [InlineData(0x07, 1)]
        [InlineData(0x08, 1)]
        [InlineData(0x0A, 1)]
        public void RecognizesProxyToContainerEnvelope(int code, int payload)
        {
            Assert.True(Inspect(Packet(code: (byte)code, payloadLength: payload), out var found));
            Assert.True(found.ProxyToContainer);
            Assert.Equal((byte)code, found.MessageCode);
        }

        [Theory]
        [InlineData(0x03, 3)]
        [InlineData(0x04, 3)]
        [InlineData(0x05, 2)]
        [InlineData(0x06, 3)]
        [InlineData(0x09, 1)]
        public void RecognizesContainerToProxyEnvelope(int code, int payload)
        {
            Assert.True(Inspect(Packet(false, (byte)code, payload), out var found));
            Assert.False(found.ProxyToContainer);
            Assert.Equal((byte)code, found.MessageCode);
        }

        [Fact] public void HttpTlsAndUnknownMagicAreRejected()
        {
            Assert.False(Inspect(System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1"), out _));
            Assert.False(Inspect(new byte[] { 0x16, 3, 3, 0, 1, 0 }, out _));
            var data = Packet(); data[0] = 0x13; Assert.False(Inspect(data, out _));
        }

        [Fact] public void WrongDirectionAndUnsupportedCodesAreRejected()
        {
            Assert.False(Inspect(Packet(code: 0x09), out _));
            Assert.False(Inspect(Packet(false, 0x0A), out _));
            Assert.False(Inspect(Packet(code: 0xFF), out _));
        }

        [Fact] public void TruncationDeclaredLengthAndOverlongAreRejected()
        {
            Assert.False(Inspect(new byte[4], out _));
            var data = Packet(); data[3]++; Assert.False(Inspect(data, out _));
            Assert.False(Inspect(new byte[8193], out _));
        }

        [Fact] public void FixedSizeCommandsAndBodyPacketsAreFailClosed()
        {
            Assert.False(Inspect(Packet(code: 0x0A, payloadLength: 2), out _));
            Assert.False(Inspect(Packet(code: 0x02, payloadLength: 2), out _));
            Assert.False(Inspect(Packet(false, 0x05, 1), out _));
            Assert.False(Inspect(Packet(code: 0x00), out _)); // unprefixed body ambiguous
        }

        [Fact] public void MissingAttestationFails()
        {
            Assert.False(Inspect(Packet(), out _, complete: false));
            Assert.False(Inspect(Packet(), out _, endpoint: false));
        }

        [Fact] public void MaximumBoundIsConservativeButAccepted()
        {
            var data = Packet(code: 0x02, payloadLength: 8188);
            Assert.True(Inspect(data, out var found));
            Assert.Equal(8192, found.PacketLength);
        }

        [Fact] public void ReorderingAndRepeatsDoNotAccumulateState()
        {
            var a = Packet(code: 0x02, payloadLength: 3);
            var b = Packet(false, 0x09);
            Assert.True(Inspect(b, out var first));
            Assert.True(Inspect(a, out _));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public async Task ConcurrentInspectionIsDeterministic()
        {
            var results = await Task.WhenAll(Enumerable.Range(0, 32)
                .Select(_ => Task.Run(() => Inspect(Packet(), out var observation))));
            Assert.All(results, Assert.True);
        }

        [Fact] public void RequestPayloadAndSecretsAreNotRetained()
        {
            var a = Packet(code: 0x02, payloadLength: 5);
            var b = Packet(code: 0x02, payloadLength: 5);
            a[6] = 0x01; b[6] = 0xFE;
            Assert.True(Inspect(a, out var first));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
        }
    }
}
