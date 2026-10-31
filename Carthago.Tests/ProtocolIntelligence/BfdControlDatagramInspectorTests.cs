// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 5880 Control datagrams; not authenticated link-state evidence.
    public sealed class BfdControlDatagramInspectorTests
    {
        private static byte[] Packet(byte state = 1, bool authenticated = false,
            byte authType = 1, int authLength = 4)
        {
            int length = 24 + (authenticated ? authLength : 0);
            var data = new byte[length];
            data[0] = 0x20;
            data[1] = (byte)((state << 6) | (authenticated ? 0x04 : 0));
            data[2] = 3;
            data[3] = (byte)length;
            BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4, 4), 42);
            BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8, 4), state >= 2 ? 7u : 0u);
            BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(12, 4), 1000000);
            BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(16, 4), 1000000);
            if (authenticated)
            {
                data[24] = authType;
                data[25] = (byte)authLength;
            }
            return data;
        }

        private static bool Inspect(byte[] data, out BfdControlObservation observation,
            bool attested = true)
            => BfdControlDatagramInspector.TryInspect(data, attested, out observation);

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        public void AllFourClaimedStatesAreStructurallyObserved(int state)
        {
            Assert.True(Inspect(Packet((byte)state), out var found));
            Assert.Equal((byte)state, found.ClaimedState);
            Assert.False(found.AuthenticationPresentUnverified);
        }

        [Theory]
        [InlineData(1, 4)]
        [InlineData(2, 24)]
        [InlineData(3, 24)]
        [InlineData(4, 28)]
        [InlineData(5, 28)]
        public void SupportedAuthenticationSectionsRemainUnverified(int type, int length)
        {
            Assert.True(Inspect(Packet(authenticated: true,
                authType: (byte)type, authLength: length), out var found));
            Assert.True(found.AuthenticationPresentUnverified);
            Assert.Equal((byte)type, found.AuthenticationType);
        }

        [Fact] public void TlsHttpAndNonBfdVersionsFail()
        {
            Assert.False(Inspect(new byte[] { 0x16, 3, 3, 0, 5 }, out _));
            Assert.False(Inspect(System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1"), out _));
            var data = Packet(); data[0] = 0x40; Assert.False(Inspect(data, out _));
        }

        [Fact] public void TruncationLengthAndOverlongFail()
        {
            Assert.False(Inspect(new byte[23], out _));
            var data = Packet(); data[3] = 23; Assert.False(Inspect(data, out _));
            Assert.False(Inspect(new byte[65], out _));
        }

        [Fact] public void ReservedFlagsAndPollFinalConflictFail()
        {
            var data = Packet(); data[1] |= 0x01; Assert.False(Inspect(data, out _));
            data = Packet(); data[1] |= 0x30; Assert.False(Inspect(data, out _));
        }

        [Fact] public void InvalidDiscriminatorsAndTimerFail()
        {
            var data = Packet(); data[4] = 0; data[5] = 0; data[6] = 0; data[7] = 0;
            Assert.False(Inspect(data, out _));
            data = Packet(state: 3); data[8] = 0; data[9] = 0; data[10] = 0; data[11] = 0;
            Assert.False(Inspect(data, out _));
            data = Packet(); data.AsSpan(12, 4).Clear(); Assert.False(Inspect(data, out _));
        }

        [Fact] public void UnsupportedAuthenticationShapesFail()
        {
            Assert.False(Inspect(Packet(authenticated: true, authType: 6), out _));
            Assert.False(Inspect(Packet(authenticated: true, authType: 2, authLength: 4), out _));
            var data = Packet(authenticated: true); data[25] = 5;
            Assert.False(Inspect(data, out _));
        }

        [Fact] public void UnattestedDatagramFailsClosed()
            => Assert.False(Inspect(Packet(), out _, attested: false));

        [Fact] public void ReorderedAndRepeatedDatagramsHaveNoState()
        {
            var a = Packet(state: 3); var b = Packet(state: 1);
            Assert.True(Inspect(b, out var first));
            Assert.True(Inspect(a, out _));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public async Task ConcurrentDatagramsAreDeterministic()
        {
            var results = await Task.WhenAll(Enumerable.Range(0, 32)
                .Select(_ => Task.Run(() => Inspect(Packet(), out _))));
            Assert.All(results, result => Assert.True(result));
        }

        [Fact] public void DiscriminatorsAndAuthenticationBytesAreNotRetained()
        {
            var a = Packet(authenticated: true);
            var b = Packet(authenticated: true);
            a[4] = 1; b[4] = 2; a[27] = 0xAA; b[27] = 0xBB;
            Assert.True(Inspect(a, out var first));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
        }
    }
}
