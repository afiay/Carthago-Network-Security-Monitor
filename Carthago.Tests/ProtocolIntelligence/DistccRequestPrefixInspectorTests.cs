// SPDX-License-Identifier: MIT
// Synthetic distcc v1/v2 prefixes only. SOURCE CANDIDATE — UNVERIFIED.
// Authored xUnit scenarios; 0 executed, no real captures or command payloads.
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class DistccRequestPrefixInspectorTests
    {
        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        public void ValidVersionedClientPrefixIsOnlyARequestShape(int version)
        {
            Assert.True(Inspect(Request(version: version), out var observation));
            Assert.Equal(version, observation.ProtocolVersion);
            Assert.Equal(2, observation.DeclaredArgumentCount);
            Assert.Equal(3, observation.FirstArgumentLength);
        }

        [Fact]
        public void ObservationDoesNotRetainFirstArgumentContents()
        {
            var data = Request(argument: "xyz");
            Assert.True(Inspect(data, out var observation));
            Assert.Equal(3, observation.FirstArgumentLength);
            Assert.DoesNotContain("xyz", observation.ToString());
        }

        [Fact]
        public void CrossProtocolPayloadIsNotDistcc()
        {
            Assert.False(Inspect(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n"), out _));
        }

        [Theory]
        [InlineData(false, true, true, true, true)]
        [InlineData(true, false, true, true, true)]
        [InlineData(true, true, false, true, true)]
        [InlineData(true, true, true, false, true)]
        [InlineData(true, true, true, true, false)]
        public void MissingProvenanceOrPlaintextAttestationFailsClosed(
            bool start, bool client, bool plaintext, bool endpoint, bool provenance)
        {
            Assert.False(DistccRequestPrefixInspector.TryInspect(
                Request(), start, client, plaintext, endpoint, provenance, out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(11)]
        [InlineData(24)]
        [InlineData(36)]
        public void TruncatedOrReorderedPrefixFailsClosed(int bytes)
        {
            Assert.False(Inspect(Request().AsSpan(0, bytes).ToArray(), out _));
        }

        [Fact]
        public void MalformedHexadecimalFailsClosed()
        {
            var data = Request();
            data[7] = (byte)'G';
            Assert.False(Inspect(data, out _));
        }

        [Fact]
        public void IncorrectTagSequenceFailsClosed()
        {
            var data = Request();
            data[12] = (byte)'A';
            data[13] = (byte)'R';
            data[14] = (byte)'G';
            data[15] = (byte)'V';
            Assert.False(Inspect(data, out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(3)]
        [InlineData(4)]
        public void UnsupportedProtocolVersionFailsClosed(int version)
        {
            Assert.False(Inspect(Request(version: version), out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(129)]
        public void OutOfBoundArgumentCountFailsClosed(int count)
        {
            Assert.False(Inspect(Request(count: count), out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(257)]
        public void EmptyOrOversizedFirstArgumentFailsClosed(int length)
        {
            Assert.False(Inspect(Request(argument: new string('x', length)), out _));
        }

        [Fact]
        public void DeclaredFirstArgumentLengthCannotExceedAvailableBytes()
        {
            var data = Request();
            data[35] = (byte)'8'; // ARGV 00000008, only three bytes follow.
            Assert.False(Inspect(data, out _));
        }

        [Fact]
        public void OversizedPrefixFailsClosedWithoutAllocation()
        {
            Assert.False(Inspect(new byte[4097], out _));
        }

        [Fact]
        public void ParallelInspectionsAreDeterministicAndStateless()
        {
            var data = Request();
            Parallel.For(0, 64, _ =>
            {
                Assert.True(Inspect(data, out var result));
                Assert.Equal(2, result.DeclaredArgumentCount);
            });
        }

        [Fact]
        public void RepeatedAndOutOfOrderCallsDoNotCreateState()
        {
            var valid = Request();
            var invalid = valid.Skip(12).ToArray();
            Assert.True(Inspect(valid, out _));
            Assert.False(Inspect(invalid, out _));
            Assert.True(Inspect(valid, out _));
        }

        [Fact]
        public void CiphertextOrNonInitialTcpDataIsNotInterpreted()
        {
            var data = Request();
            Assert.False(DistccRequestPrefixInspector.TryInspect(
                data, true, true, false, true, true, out _));
            Assert.False(DistccRequestPrefixInspector.TryInspect(
                data, false, true, true, true, true, out _));
        }

        private static bool Inspect(
            byte[] data, out DistccRequestPrefixObservation observation)
            => DistccRequestPrefixInspector.TryInspect(
                data, true, true, true, true, true, out observation);

        private static byte[] Request(
            int version = 1, int count = 2, string argument = "gcc")
            => Encoding.ASCII.GetBytes(
                $"DIST{version:X8}ARGC{count:X8}ARGV{argument.Length:X8}{argument}");
    }
}
