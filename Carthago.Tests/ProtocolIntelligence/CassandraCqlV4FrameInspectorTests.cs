// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic CQL v4 envelopes, never authenticated server outcomes or queries.
    public sealed class CassandraCqlV4FrameInspectorTests
    {
        private static byte[] Frame(byte opcode = 0x05, bool response = false,
            byte flags = 0, short stream = 0, byte[]? body = null)
        {
            body ??= Array.Empty<byte>();
            var data = new byte[9 + body.Length];
            data[0] = response ? (byte)0x84 : (byte)0x04;
            data[1] = flags;
            BinaryPrimitives.WriteInt16BigEndian(data.AsSpan(2, 2), stream);
            data[4] = opcode;
            BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(5, 4), (uint)body.Length);
            body.CopyTo(data, 9);
            return data;
        }

        private static bool Inspect(byte[] data, out CassandraCqlV4Observation found,
            bool attested = true)
            => CassandraCqlV4FrameInspector.TryInspect(data, attested, out found);

        [Theory]
        [InlineData(0x05)]
        [InlineData(0x07)]
        [InlineData(0x09)]
        [InlineData(0x0a)]
        [InlineData(0x0d)]
        public void SupportedRequestOpcodesAreStructurallyRecognized(int opcode)
        {
            Assert.True(Inspect(Frame((byte)opcode, body: opcode == 0x05 
                ? Array.Empty<byte>() : new byte[] { 0, 1, 2, 3 }), out var found));
            Assert.False(found.IsResponse);
            Assert.Equal((byte)opcode, found.Opcode);
        }

        [Theory]
        [InlineData(0x00)]
        [InlineData(0x02)]
        [InlineData(0x08)]
        [InlineData(0x10)]
        public void SupportedResponsesAreNotClaimsOfSuccess(int opcode)
        {
            Assert.True(Inspect(Frame((byte)opcode, response: true), out var found));
            Assert.True(found.IsResponse);
        }

        [Fact] public void StartupWithUncompressedBodyIsRecognized()
            => Assert.True(Inspect(Frame(0x01, body: new byte[] { 0, 0 }), out _));

        [Fact] public void ServerPushEventRequiresReservedStreamMinusOne()
        {
            Assert.True(Inspect(Frame(0x0c, response: true, stream: -1), out _));
            Assert.False(Inspect(Frame(0x0c, response: true, stream: 0), out _));
        }

        [Fact] public void CompressedQueryIsOpaqueMetadataOnly()
        {
            Assert.True(Inspect(Frame(0x07, flags: 1, body: new byte[] { 0x99 }), out var found));
            Assert.True(found.CompressedBodyOpaque);
        }

        [Fact] public void CustomPayloadFlagOnlyAllowedForSupportingRequests()
        {
            Assert.True(Inspect(Frame(0x07, flags: 4), out var found));
            Assert.True(found.CustomPayloadFlag);
            Assert.False(Inspect(Frame(0x05, flags: 4), out _));
        }

        [Fact] public void TlsHttpAndOtherProtocolsAreNotCql()
        {
            Assert.False(Inspect(new byte[] { 0x16, 3, 3, 0, 5, 0, 0, 0, 0 }, out _));
            Assert.False(Inspect(System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1"), out _));
        }

        [Fact] public void WrongVersionAndDirectionFail()
        {
            var data = Frame(); data[0] = 0x05; Assert.False(Inspect(data, out _));
            Assert.False(Inspect(Frame(0x02), out _));
            Assert.False(Inspect(Frame(0x07, response: true), out _));
        }

        [Fact] public void InvalidStreamDirectionFails()
        {
            Assert.False(Inspect(Frame(0x05, stream: -1), out _));
            Assert.False(Inspect(Frame(0x08, response: true, stream: -1), out _));
        }

        [Fact] public void InvalidFlagsAndRequestWarningsFail()
        {
            Assert.False(Inspect(Frame(flags: 0x80), out _));
            Assert.False(Inspect(Frame(flags: 0x08), out _));
        }

        [Fact] public void StartupCannotBeCompressedAndMustHaveBody()
        {
            Assert.False(Inspect(Frame(0x01), out _));
            Assert.False(Inspect(Frame(0x01, flags: 1, body: new byte[] { 0, 0 }), out _));
        }

        [Fact] public void ReadyAndOptionsMustBeEmpty()
        {
            Assert.False(Inspect(Frame(0x05, body: new byte[] { 1 }), out _));
            Assert.False(Inspect(Frame(0x02, response: true, body: new byte[] { 1 }), out _));
        }

        [Fact] public void TruncatedDeclaredAndOversizeFramesFail()
        {
            Assert.False(Inspect(new byte[8], out _));
            var data = Frame(); data[8] = 1; Assert.False(Inspect(data, out _));
            Assert.False(Inspect(new byte[16385], out _));
        }

        [Fact] public void UntrustedOrEncryptedBoundaryIsRejected()
            => Assert.False(Inspect(Frame(), out _, attested: false));

        [Fact] public void OutOfOrderAndRepeatedFramesHaveNoState()
        {
            var a = Frame(0x05); var b = Frame(0x08, response: true);
            Assert.True(Inspect(b, out var first));
            Assert.True(Inspect(a, out _));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public async Task ConcurrentFramesAreDeterministic()
        {
            var outcomes = await Task.WhenAll(Enumerable.Range(0, 32)
                .Select(i => Task.Run(() => Inspect(Frame(), out _))));
            Assert.All(outcomes, outcome => Assert.True(outcome));
        }

        [Fact] public void StreamIdsAndCqlTextAreNeverRetained()
        {
            var a = Frame(0x07, stream: 1, body: new byte[] { 1, 2, 3, 4 });
            var b = Frame(0x07, stream: 2, body: new byte[] { 5, 6, 7, 8 });
            Assert.True(Inspect(a, out var first));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
        }
    }
}