// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic OpenFlow v1.3 envelopes; no controller acceptance or flow effect.
    public sealed class OpenFlow13EnvelopeInspectorTests
    {
        private static byte[] Message(byte type = 0, int length = 8, uint xid = 1)
        {
            var data = new byte[length];
            data[0] = 4;
            data[1] = type;
            BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(2, 2), (ushort)length);
            BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4, 4), xid);
            return data;
        }

        private static bool Inspect(byte[] data, out OpenFlow13EnvelopeObservation observation,
            bool attested = true)
            => OpenFlow13EnvelopeInspector.TryInspect(data, attested, out observation);

        [Theory]
        [InlineData(0)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(5)]
        [InlineData(7)]
        [InlineData(20)]
        [InlineData(21)]
        public void RecognizesSupportedHeaderOnlyMessages(int type)
        {
            Assert.True(Inspect(Message((byte)type), out var found));
            Assert.Equal((byte)type, found.MessageType);
            Assert.False(found.ClaimedFlowModification);
        }

        [Fact] public void FlowModIsOnlyAClaimedMessageType()
        {
            Assert.True(Inspect(Message(14, 56), out var found));
            Assert.True(found.ClaimedFlowModification);
            Assert.False(Inspect(Message(14, 55), out _));
        }

        [Fact] public void MultipartRequiresMinimumEnvelope()
        {
            Assert.True(Inspect(Message(18, 16), out _));
            Assert.True(Inspect(Message(19, 16), out _));
            Assert.False(Inspect(Message(18, 8), out _));
        }

        [Fact] public void TlsHttpAndOtherVersionsFail()
        {
            Assert.False(Inspect(new byte[] { 0x16, 3, 3, 0, 5, 0, 0, 0 }, out _));
            Assert.False(Inspect(System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1"), out _));
            var data = Message(); data[0] = 0x06; Assert.False(Inspect(data, out _));
        }

        [Fact] public void UnknownTypeAndFixedSizeViolationsFail()
        {
            Assert.False(Inspect(Message(255), out _));
            Assert.False(Inspect(Message(5, 9), out _));
            Assert.False(Inspect(Message(1, 8), out _));
        }

        [Fact] public void TruncatedDeclaredAndOversizeFail()
        {
            Assert.False(Inspect(new byte[7], out _));
            var data = Message(); data[3] = 9; Assert.False(Inspect(data, out _));
            Assert.False(Inspect(new byte[4097], out _));
        }

        [Fact] public void UnattestedPlaintextMessageFails()
            => Assert.False(Inspect(Message(), out _, attested: false));

        [Fact] public void OutOfOrderAndRepeatedMessagesHaveNoState()
        {
            var a = Message(14, 56); var b = Message(20);
            Assert.True(Inspect(b, out var first));
            Assert.True(Inspect(a, out _));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public async Task ConcurrentMessagesAreDeterministic()
        {
            var results = await Task.WhenAll(Enumerable.Range(0, 32)
                .Select(_ => Task.Run(() => Inspect(Message(), out _))));
            Assert.All(results, result => Assert.True(result));
        }

        [Fact] public void XidAndBodyNeverEnterObservation()
        {
            var a = Message(14, 56, xid: 1);
            var b = Message(14, 56, xid: 200);
            a[12] = 0xFE; b[12] = 0xCC;
            Assert.True(Inspect(a, out var first));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
        }
    }
}
