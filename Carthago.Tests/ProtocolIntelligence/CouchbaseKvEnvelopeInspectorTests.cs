// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic Couchbase-compatible KV frames; no authenticated endpoint or traffic.
    public sealed class CouchbaseKvEnvelopeInspectorTests
    {
        private static byte[] Frame(byte magic = 0x80, byte opcode = 0,
            byte[]? key = null, byte[]? extras = null, byte[]? value = null,
            byte[]? framing = null, ushort status = 0)
        {
            key ??= new byte[] { (byte)'k' };
            extras ??= Array.Empty<byte>();
            value ??= Array.Empty<byte>();
            framing ??= Array.Empty<byte>();
            bool flexible = magic is 0x08 or 0x18;
            int body = framing.Length + extras.Length + key.Length + value.Length;
            var data = new byte[24 + body];
            data[0] = magic; data[1] = opcode;
            if (flexible)
            {
                data[2] = (byte)framing.Length; data[3] = (byte)key.Length;
            }
            else
                BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(2, 2), (ushort)key.Length);
            data[4] = (byte)extras.Length;
            if (magic is 0x81 or 0x18)
                BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(6, 2), status);
            BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8, 4), (uint)body);
            int cursor = 24;
            framing.CopyTo(data, cursor); cursor += framing.Length;
            extras.CopyTo(data, cursor); cursor += extras.Length;
            key.CopyTo(data, cursor); cursor += key.Length;
            value.CopyTo(data, cursor);
            data[12] = 0x5a; data[16] = 0x7b; // Opaque/CAS never retained.
            return data;
        }

        private static bool Inspect(byte[] data, out CouchbaseKvObservation found,
            bool attested = true, bool trustedEndpoint = true)
            => CouchbaseKvEnvelopeInspector.TryInspect(data, attested, trustedEndpoint, out found);

        [Fact] public void ClassicGetHasOnlyNonSensitiveLengths()
        {
            Assert.True(Inspect(Frame(), out var found));
            Assert.Equal((byte)0, found.Opcode);
            Assert.Equal(1, found.KeyLength);
            Assert.Equal(0, found.ValueLength);
        }

        [Fact] public void SetRequiresEightByteExtras()
        {
            Assert.True(Inspect(Frame(opcode: 1, extras: new byte[8], value: new byte[] { 1 }),
                out var found));
            Assert.Equal(1, found.ValueLength);
            Assert.False(Inspect(Frame(opcode: 1), out _));
        }

        [Fact] public void DeleteRequiresKeyAndNoValue()
        {
            Assert.True(Inspect(Frame(opcode: 4), out _));
            Assert.False(Inspect(Frame(opcode: 4, value: new byte[] { 1 }), out _));
        }

        [Theory]
        [InlineData(0x1f)]
        [InlineData(0x21)]
        [InlineData(0x50)]
        [InlineData(0x89)]
        public void CouchbaseSpecificOpcodesAreEnvelopeHints(int opcode)
        {
            Assert.True(Inspect(Frame(opcode: (byte)opcode), out var found));
            Assert.Equal((byte)opcode, found.Opcode);
        }

        [Fact] public void FlexibleFramingIsStructurallyWalked()
        {
            Assert.True(Inspect(Frame(magic: 0x08, framing: new byte[] { 0x00 }),
                out var found));
            Assert.True(found.FlexibleFraming);
        }

        [Fact] public void ClaimedResponseStatusIsNotAnAuthenticatedOutcome()
        {
            Assert.True(Inspect(Frame(magic: 0x81, status: 0x0008), out var found));
            Assert.True(found.IsResponse);
            Assert.Equal((ushort?)8, found.ClaimedResponseStatus);
        }

        [Fact] public void FlexibleResponseFramingIsAccepted()
        {
            Assert.True(Inspect(Frame(magic: 0x18, framing: new byte[] { 0x00 }),
                out var found));
            Assert.True(found.IsResponse);
        }

        [Fact] public void GenericMemcachedMagicWithoutEndpointProvenanceFails()
            => Assert.False(Inspect(Frame(), out _, trustedEndpoint: false));

        [Fact] public void UnattestedPlaintextBoundaryFails()
            => Assert.False(Inspect(Frame(), out _, attested: false));

        [Fact] public void HttpTlsAndUnknownMagicAreRejected()
        {
            Assert.False(Inspect(System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n"), out _));
            var data = Frame(); data[0] = 0x16; Assert.False(Inspect(data, out _));
        }

        [Fact] public void UnsupportedOpcodeAndReservedDataTypeFail()
        {
            var data = Frame(); data[1] = 0xfe; Assert.False(Inspect(data, out _));
            data = Frame(); data[5] = 0x80; Assert.False(Inspect(data, out _));
        }

        [Fact] public void BodyLengthMustMatchExactBoundary()
        {
            var data = Frame(); data[11] = 99; Assert.False(Inspect(data, out _));
            data = Frame(); Array.Resize(ref data, data.Length + 1);
            Assert.False(Inspect(data, out _));
        }

        [Fact] public void KeyAndExtrasCannotExceedBody()
        {
            var data = Frame(); data[3] = 100; Assert.False(Inspect(data, out _));
            data = Frame(); data[4] = 200; Assert.False(Inspect(data, out _));
        }

        [Fact] public void MalformedFlexibleFrameInfoFailsClosed()
        {
            Assert.False(Inspect(Frame(magic: 0x08, framing: new byte[] { 0x01 }), out _));
            Assert.False(Inspect(Frame(magic: 0x08, framing: new byte[] { 0xf0 }), out _));
            Assert.False(Inspect(Frame(magic: 0x08, framing: new byte[] { 0x0f }), out _));
        }

        [Fact] public void ExcessiveFrameInfoCountIsBounded()
        {
            Assert.False(Inspect(Frame(magic: 0x08, framing: new byte[33]), out _));
        }

        [Fact] public void TruncatedAndOversizedMessagesFail()
        {
            Assert.False(Inspect(new byte[23], out _));
            Assert.False(Inspect(new byte[16409], out _));
        }

        [Fact] public void OutOfOrderAndDuplicateMessagesAreStateless()
        {
            var a = Frame(opcode: 4); var b = Frame();
            Assert.True(Inspect(a, out _));
            Assert.True(Inspect(b, out var first));
            Assert.True(Inspect(a, out _));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public async Task ParallelFramesAreDeterministic()
        {
            var outcomes = await Task.WhenAll(Enumerable.Range(0, 32)
                .Select(i => Task.Run(() => Inspect(Frame(), out _))));
            Assert.All(outcomes, outcome => Assert.True(outcome));
        }

        [Fact] public void KeysOpaqueIdsAndCasAreNeverRetained()
        {
            var a = Frame(key: new byte[] { (byte)'a' });
            var b = Frame(key: new byte[] { (byte)'b' });
            b[12] = 0xff; b[16] = 0xee;
            Assert.True(Inspect(a, out var first));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
        }
    }
}