// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic TDS 7.x packet envelopes, not SQL login or execution evidence.
    public sealed class TdsPacketEnvelopeInspectorTests
    {
        private static byte[] Packet(byte type = 0x12, int bodyLength = 16,
            byte status = 1, byte packetId = 1)
        {
            var data = new byte[8 + bodyLength];
            data[0] = type;
            data[1] = status;
            BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(2, 2), (ushort)data.Length);
            data[6] = packetId;
            return data;
        }

        private static bool Inspect(byte[] bytes, out TdsPacketEnvelopeObservation observation,
            bool attested = true)
            => TdsPacketEnvelopeInspector.TryInspect(bytes, attested, out observation);

        [Theory]
        [InlineData(0x01)]
        [InlineData(0x03)]
        [InlineData(0x04)]
        [InlineData(0x10)]
        [InlineData(0x12)]
        public void RecognizesSupportedMessageEnvelopeTypes(int type)
        {
            Assert.True(Inspect(Packet((byte)type), out var found));
            Assert.Equal((byte)type, found.PacketType);
            Assert.True(found.EndOfMessage);
        }

        [Fact] public void AttentionHasNoPayload()
        {
            Assert.True(Inspect(Packet(0x06, 0), out var found));
            Assert.Equal(8, found.PacketLength);
            Assert.False(Inspect(Packet(0x06, 1), out _));
        }

        [Fact] public void PreloginMayCarryOpaqueTls()
        {
            Assert.True(Inspect(Packet(), out var found));
            Assert.True(found.PreloginMayEncapsulateTls);
            Assert.False(Inspect(Packet(0x01), out found) && found.PreloginMayEncapsulateTls);
        }

        [Fact] public void TlsHttpAndUnknownTypesFailClosed()
        {
            Assert.False(Inspect(new byte[] { 0x16, 3, 3, 0, 5, 0, 0, 0 }, out _));
            Assert.False(Inspect(System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1"), out _));
            Assert.False(Inspect(Packet(0xFF), out _));
        }

        [Fact] public void TruncationLengthMismatchAndOversizeFail()
        {
            Assert.False(Inspect(new byte[7], out _));
            var truncated = Packet(); truncated[3]++; Assert.False(Inspect(truncated, out _));
            Assert.False(Inspect(new byte[4097], out _));
        }

        [Fact] public void ReservedStatusAndWindowFail()
        {
            Assert.False(Inspect(Packet(status: 0x80), out _));
            Assert.False(Inspect(Packet(status: 0x18), out _));
            var data = Packet(); data[7] = 1; Assert.False(Inspect(data, out _));
        }

        [Fact] public void EmptyNonAttentionPacketFails()
            => Assert.False(Inspect(Packet(0x12, 0), out _));

        [Fact] public void MissingPlaintextBoundaryAttestationFails()
            => Assert.False(Inspect(Packet(), out _, attested: false));

        [Fact] public void ReorderedRepeatedPacketsRemainIndependent()
        {
            var a = Packet(0x01, 1, status: 0, packetId: 7);
            var b = Packet(0x12, 2, packetId: 1);
            Assert.True(Inspect(b, out var first));
            Assert.True(Inspect(a, out _));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public async Task ConcurrentIndependentPacketsAreDeterministic()
        {
            var results = await Task.WhenAll(Enumerable.Range(0, 32)
                .Select(_ => Task.Run(() => Inspect(Packet(), out _))));
            Assert.All(results, result => Assert.True(result));
        }

        [Fact] public void PacketIdAndPayloadAreNotRetained()
        {
            var a = Packet(packetId: 1);
            var b = Packet(packetId: 8);
            a[8] = 0x12; b[8] = 0xFE;
            Assert.True(Inspect(a, out var first));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
        }
    }
}
