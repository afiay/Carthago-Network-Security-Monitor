// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 1831/1833 XDR calls; no live RPC, credentials or outcomes.
    public sealed class PortmapV2CallInspectorTests
    {
        private static void Put(byte[] data, int offset, uint value)
            => BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset, 4), value);

        private static byte[] Call(uint procedure = 3, uint program = 100003,
            uint protocol = 6, uint port = 0, byte[]? credential = null)
        {
            credential ??= Array.Empty<byte>();
            int padded = (credential.Length + 3) & ~3;
            int authSize = 8 + padded + 8;
            int argSize = procedure is 1 or 2 or 3 ? 16 : 0;
            var data = new byte[24 + authSize + argSize];
            Put(data, 0, 0x12345678); // XID is deliberately not retained.
            Put(data, 8, 2); Put(data, 12, 100000); Put(data, 16, 2);
            Put(data, 20, procedure);
            Put(data, 24, credential.Length == 0 ? 0u : 1u);
            Put(data, 28, (uint)credential.Length);
            credential.CopyTo(data, 32);
            int cursor = 32 + padded + 8;
            if (argSize != 0)
            {
                Put(data, cursor, program);
                Put(data, cursor + 4, 3);
                Put(data, cursor + 8, protocol);
                Put(data, cursor + 12, port);
            }
            return data;
        }

        private static bool Inspect(byte[] data, out PortmapCallObservation result,
            bool attested = true, PortmapTransport transport = PortmapTransport.Udp)
            => PortmapV2CallInspector.TryInspect(data, transport, attested, out result);

        [Theory]
        [InlineData(0u)]
        [InlineData(4u)]
        public void NullAndDumpCallsHaveNoArguments(uint procedure)
        {
            Assert.True(Inspect(Call(procedure), out var found));
            Assert.Equal((byte)procedure, found.Procedure);
            Assert.Equal(0u, found.TargetProgram);
        }

        [Theory]
        [InlineData(1u, 2049u)]
        [InlineData(2u, 0u)]
        [InlineData(3u, 0u)]
        public void MappingOperationsExposeOnlyTypedMetadata(uint procedure, uint port)
        {
            Assert.True(Inspect(Call(procedure, port: port), out var found));
            Assert.Equal(100003u, found.TargetProgram);
            Assert.Equal((ushort)port, found.RequestedPort);
        }

        [Fact] public void TcpMessageRequiresCallerAttestedRecordBoundary()
        {
            Assert.True(Inspect(Call(), out _, transport: PortmapTransport.Tcp));
            Assert.False(Inspect(Call(), out _, attested: false, transport: PortmapTransport.Tcp));
        }

        [Fact] public void PaddedAuthBytesAreSkippedWithoutRetention()
        {
            var call = Call(3, credential: new byte[] { 1, 2, 3 });
            Assert.True(Inspect(call, out var found));
            Assert.Equal((byte)3, found.Procedure);
            Assert.Equal(call.Length, found.MessageLength);
        }

        [Fact] public void HttpTlsAndShortCrossProtocolInputsFail()
        {
            Assert.False(Inspect(System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1"), out _));
            Assert.False(Inspect(new byte[] { 0x16, 3, 3, 0, 5 }, out _));
            Assert.False(Inspect(new byte[39], out _));
        }

        [Fact] public void NonRpcAndWrongProgramAreRejected()
        {
            var bytes = Call(); Put(bytes, 4, 1); Assert.False(Inspect(bytes, out _));
            bytes = Call(); Put(bytes, 12, 100003); Assert.False(Inspect(bytes, out _));
            bytes = Call(); Put(bytes, 8, 3); Assert.False(Inspect(bytes, out _));
        }

        [Fact] public void VersionAndUnimplementedCallitFailClosed()
        {
            var bytes = Call(); Put(bytes, 16, 3); Assert.False(Inspect(bytes, out _));
            Assert.False(Inspect(Call(5), out _));
        }

        [Fact] public void InvalidMappingTransportAndPortFail()
        {
            Assert.False(Inspect(Call(1, protocol: 99, port: 2049), out _));
            Assert.False(Inspect(Call(1, port: 0), out _));
            Assert.False(Inspect(Call(3, port: 65536), out _));
        }

        [Fact] public void UnknownInputTransportCannotBeAssumed()
            => Assert.False(Inspect(Call(), out _, transport: PortmapTransport.Unknown));

        [Fact] public void TruncatedCredentialAndExcessiveCredentialFail()
        {
            var bytes = Call(3, credential: new byte[] { 1, 2, 3 });
            Array.Resize(ref bytes, bytes.Length - 1);
            Assert.False(Inspect(bytes, out _));
            bytes = Call(); Put(bytes, 28, 401);
            Assert.False(Inspect(bytes, out _));
        }

        [Fact] public void NonzeroXdrPaddingFailsStrictProfile()
        {
            var bytes = Call(3, credential: new byte[] { 1, 2, 3 });
            bytes[35] = 1;
            Assert.False(Inspect(bytes, out _));
        }

        [Fact] public void TrailingBytesAndExcessiveSizeFail()
        {
            var bytes = Call(); Array.Resize(ref bytes, bytes.Length + 1);
            Assert.False(Inspect(bytes, out _));
            Assert.False(Inspect(new byte[2049], out _));
        }

        [Fact] public void NullAndDumpWithInjectedArgumentsFail()
        {
            var bytes = Call(0); Array.Resize(ref bytes, bytes.Length + 4);
            Assert.False(Inspect(bytes, out _));
            bytes = Call(4); Array.Resize(ref bytes, bytes.Length + 16);
            Assert.False(Inspect(bytes, out _));
        }

        [Fact] public void ReorderedAndRepeatedCallsAreStateless()
        {
            var a = Call(1, port: 2049); var b = Call(3);
            Assert.True(Inspect(b, out var first));
            Assert.True(Inspect(a, out _));
            Assert.True(Inspect(b, out var again));
            Assert.Equal(first, again);
        }

        [Fact] public async Task ParallelIndependentCallsRemainDeterministic()
        {
            var outcomes = await Task.WhenAll(Enumerable.Range(0, 32)
                .Select(i => Task.Run(() => Inspect(Call(3), out _))));
            Assert.All(outcomes, outcome => Assert.True(outcome));
        }

        [Fact] public void XidAndAuthenticationAreNotReported()
        {
            var a = Call(3, credential: new byte[] { 1, 2, 3 });
            var b = (byte[])a.Clone(); Put(b, 0, 0xDEADBEEF);
            Assert.True(Inspect(a, out var first));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
        }
    }
}