// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic XDR-shaped Firebird PDUs based on Firebird wire protocol v0.18.
    // No real credentials, database paths, live capture or exploitation fixtures.
    public sealed class FirebirdWirePduInspectorTests
    {
        private static void U32(List<byte> bytes, uint value)
        {
            bytes.Add((byte)(value >> 24));
            bytes.Add((byte)(value >> 16));
            bytes.Add((byte)(value >> 8));
            bytes.Add((byte)value);
        }

        private static void Opaque(List<byte> bytes, byte[] data)
        {
            U32(bytes, (uint)data.Length);
            bytes.AddRange(data);
            while (bytes.Count % 4 != 0)
                bytes.Add(0);
        }

        private static byte[] Connect(int count = 1, uint version = 3,
            byte[]? file = null, byte[]? user = null)
        {
            var bytes = new List<byte>();
            U32(bytes, 1); U32(bytes, 0); U32(bytes, version); U32(bytes, 1);
            Opaque(bytes, file ?? Encoding.ASCII.GetBytes("db"));
            U32(bytes, (uint)count);
            Opaque(bytes, user ?? new byte[] { 1, 2, 3 });
            for (int i = 0; i < count; i++)
            {
                U32(bytes, 0x800d); U32(bytes, 1); U32(bytes, 3);
                U32(bytes, 5); U32(bytes, 2);
            }
            return bytes.ToArray();
        }

        private static byte[] Attach(uint opcode = 19,
            byte[]? path = null, byte[]? dpb = null)
        {
            var bytes = new List<byte>();
            U32(bytes, opcode); U32(bytes, 0);
            Opaque(bytes, path ?? Encoding.ASCII.GetBytes("db"));
            Opaque(bytes, dpb ?? new byte[] { 1, 2, 3 });
            return bytes.ToArray();
        }

        private static byte[] Accept(uint version = 0x800d)
        {
            var bytes = new List<byte>();
            U32(bytes, 3); U32(bytes, version); U32(bytes, 1); U32(bytes, 5);
            return bytes.ToArray();
        }

        private static byte[] Callback(byte[]? data = null, uint? reply = null)
        {
            var bytes = new List<byte>();
            U32(bytes, 97);
            Opaque(bytes, data ?? new byte[] { 1, 2, 3 });
            if (reply.HasValue) U32(bytes, reply.Value);
            return bytes.ToArray();
        }

        private static bool Inspect(byte[] pdu, out FirebirdWireObservation observation,
            bool fromServer = false, bool complete = true, bool endpoint = true)
            => FirebirdWirePduInspector.TryInspect(pdu, complete, endpoint,
                fromServer, out observation);

        [Theory]
        [InlineData(2)]
        [InlineData(3)]
        public void ValidConnectNegotiationIsRecognized(int version)
        {
            Assert.True(Inspect(Connect(version: (uint)version), out var found));
            Assert.Equal((uint)1, found.OperationCode);
            Assert.Equal(1, found.OfferedVersions);
            Assert.False(found.ServerToClient);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(11)]
        public void ValidBoundedProtocolOfferCountsAreRecognized(int count)
        {
            Assert.True(Inspect(Connect(count), out var found));
            Assert.Equal(count, found.OfferedVersions);
        }

        [Theory]
        [InlineData(10)]
        [InlineData(32781)]
        public void ValidSimpleAcceptIsServerOnly(int version)
        {
            Assert.True(Inspect(Accept((uint)version), out var found, fromServer: true));
            Assert.Equal((uint)3, found.OperationCode);
            Assert.True(found.ServerToClient);
        }

        [Fact]
        public void ServerRejectIsOnlyAnEnvelopeNotProofOfFailedLogin()
        {
            var bytes = new List<byte>(); U32(bytes, 4);
            Assert.True(Inspect(bytes.ToArray(), out var found, fromServer: true));
            Assert.Equal((uint)4, found.OperationCode);
        }

        [Theory]
        [InlineData(19)]
        [InlineData(20)]
        [InlineData(82)]
        public void ValidClientAttachCreateAndServiceAttachShapes(int opcode)
        {
            Assert.True(Inspect(Attach((uint)opcode), out var found));
            Assert.Equal((uint)opcode, found.OperationCode);
        }

        [Fact]
        public void CallbackShapeWithAndWithoutReplyLengthIsAccepted()
        {
            Assert.True(Inspect(Callback(), out var client));
            Assert.True(Inspect(Callback(reply: 0), out var clientWithReply));
            Assert.True(Inspect(Callback(reply: 64), out var server, fromServer: true));
            Assert.True(client.CallbackShapeOnly);
            Assert.True(clientWithReply.CallbackShapeOnly);
            Assert.True(server.CallbackShapeOnly);
        }

        [Fact]
        public void WrongDirectionCannotImpersonateServerOrClient()
        {
            Assert.False(Inspect(Connect(), out _, fromServer: true));
            Assert.False(Inspect(Accept(), out _));
            Assert.False(Inspect(Attach(), out _, fromServer: true));
            var reject = new List<byte>(); U32(reject, 4);
            Assert.False(Inspect(reject.ToArray(), out _));
        }

        [Fact]
        public void PortHintsDoNotReplaceVerifiedEndpointProvenance()
            => Assert.False(Inspect(Connect(), out _, endpoint: false));

        [Fact]
        public void IncompleteTcpSegmentCannotBePromotedToCompletePdu()
            => Assert.False(Inspect(Connect(), out _, complete: false));

        [Fact]
        public void TruncatedConnectAndAcceptFailClosed()
        {
            var connect = Connect();
            for (int i = 0; i < connect.Length; i++)
                Assert.False(Inspect(connect.Take(i).ToArray(), out _));
            Assert.False(Inspect(Accept().Take(15).ToArray(), out _, fromServer: true));
        }

        [Fact]
        public void OversizedPduIsRejectedBeforeParsing()
            => Assert.False(Inspect(new byte[4097], out _));

        [Fact]
        public void HugeOpaqueLengthIsRejectedBeforeSlicing()
        {
            var bytes = Connect();
            bytes[16] = 0x7f; bytes[17] = 0xff;
            Assert.False(Inspect(bytes, out _));
        }

        [Fact]
        public void XdrPaddingMustBeZero()
        {
            var bytes = Connect(file: new byte[] { 42 });
            bytes[21] = 1;
            Assert.False(Inspect(bytes, out _));
        }

        [Fact]
        public void UnexpectedTrailingBytesFailClosed()
        {
            Assert.False(Inspect(Connect().Concat(new byte[] { 0 }).ToArray(), out _));
            Assert.False(Inspect(Attach().Concat(new byte[] { 0 }).ToArray(), out _));
        }

        [Fact]
        public void OfferCountMismatchAndOutOfRangeAreRejected()
        {
            var count12 = Connect(12);
            Assert.False(Inspect(count12, out _));
            var truncated = Connect(2).Take(Connect(2).Length - 20).ToArray();
            Assert.False(Inspect(truncated, out _));
        }

        [Fact]
        public void InvalidVersionArchitectureAndConnectionTypeAreRejected()
        {
            var bad = Connect(version: 1);
            Assert.False(Inspect(bad, out _));
            bad = Connect(); bad[15] = 0;
            Assert.False(Inspect(bad, out _));
            var accept = Accept(99);
            Assert.False(Inspect(accept, out _, fromServer: true));
            accept = Accept(); accept[15] = 0;
            Assert.False(Inspect(accept, out _, fromServer: true));
        }

        [Fact]
        public void MalformedCallbackAndClientReplySizeFailClosed()
        {
            Assert.False(Inspect(Callback(reply: 12), out _));
            var bad = Callback(); bad[4] = 0x7f;
            Assert.False(Inspect(bad, out _));
            Assert.False(Inspect(Callback().Concat(new byte[] { 1 }).ToArray(), out _));
        }

        [Fact]
        public void UnrelatedAndUndecodedOperationCodesAreNotClaimed()
        {
            foreach (uint opcode in new uint[] { 0, 9, 60, 94, 98, 0x01020304 })
            {
                var bytes = new List<byte>(); U32(bytes, opcode);
                Assert.False(Inspect(bytes.ToArray(), out _));
            }
        }

        [Fact]
        public void HttpTlsAndEncryptedApplicationBytesFailClosed()
        {
            Assert.False(Inspect(Encoding.ASCII.GetBytes("GET / HTTP/1.1"), out _));
            Assert.False(Inspect(new byte[] { 0x16, 3, 3, 0, 5, 1, 2, 3 }, out _));
            Assert.False(Inspect(Connect(), out _, complete: false));
        }

        [Fact]
        public void IdentityDatabasePathAndDpbContentAreNeverReturned()
        {
            var first = Attach(path: Encoding.ASCII.GetBytes("one"),
                dpb: new byte[] { 1, 2, 3 });
            var second = Attach(path: Encoding.ASCII.GetBytes("two"),
                dpb: new byte[] { 9, 8, 7 });
            Assert.True(Inspect(first, out var a));
            Assert.True(Inspect(second, out var b));
            Assert.Equal(a, b);
            Assert.DoesNotContain("one", a.ToString(), StringComparison.Ordinal);
        }

        [Fact]
        public void CallbackDataAndPotentialCredentialsStayPrivate()
        {
            Assert.True(Inspect(Callback(new byte[] { 1, 2, 3 }), out var a));
            Assert.True(Inspect(Callback(new byte[] { 9, 8, 7 }), out var b));
            Assert.Equal(a, b);
        }

        [Fact]
        public void RetransmissionsAndOutOfOrderCallsCreateNoState()
        {
            var first = Connect();
            var second = Attach();
            Assert.True(Inspect(first, out var a));
            Assert.True(Inspect(second, out _));
            Assert.True(Inspect(first, out var c));
            Assert.Equal(a, c);
        }

        [Fact]
        public async Task ConcurrentClassificationIsDeterministic()
        {
            var pdu = Connect();
            var found = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ =>
                Task.Run(() =>
                {
                    Assert.True(Inspect(pdu, out var value));
                    return value;
                })));
            Assert.All(found, item => Assert.Equal(found[0], item));
        }

        [Fact]
        public void RejectionResetsOutputAndDoesNotCreateSecurityVerdict()
        {
            Assert.False(Inspect(new byte[] { 0, 0, 0, 97 }, out var result));
            Assert.Equal(default(FirebirdWireObservation), result);
        }
    }
}
