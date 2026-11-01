// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic, non-secret source fixtures. TESTS AUTHORED; 0 EXECUTED.
    public sealed class RshRequestInspectorTests
    {
        private static byte[] Request(string port = "0", string clientUser = "labclient",
            string targetUser = "labtarget", string command = "uptime")
            => Encoding.ASCII.GetBytes(
                port + "\0" + clientUser + "\0" + targetUser + "\0" + command + "\0");

        private static bool Inspect(ReadOnlySpan<byte> request,
            out RshRequestObservation observation)
            => RshRequestInspector.TryInspect(request, 700, 514,
                true, true, true, true, true, true, out observation);

        [Theory]
        [InlineData("0", 0)]
        [InlineData("512", 512)]
        [InlineData("1023", 1023)]
        public void ValidCompleteRshRequestReturnsOnlyBoundedMetadata(string port, int expected)
        {
            Assert.True(Inspect(Request(port: port), out var result));
            Assert.Equal(expected, result.StandardErrorPort);
            Assert.True(result.HasCommandField);
        }

        [Fact]
        public void LegitimateCommandWithSpacesAndTabsIsSyntacticallyAccepted()
            => Assert.True(Inspect(Request(command: "ls -l\t/tmp"), out _));

        [Fact]
        public void SshBannerDoesNotMatchRsh()
            => Assert.False(Inspect(Encoding.ASCII.GetBytes("SSH-2.0-OpenSSH_9.0\r\n"), out _));

        [Fact]
        public void HttpRequestDoesNotMatchRsh()
            => Assert.False(Inspect(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n"), out _));

        [Theory]
        [InlineData("1")]
        [InlineData("511")]
        [InlineData("1024")]
        [InlineData("65535")]
        [InlineData("x")]
        [InlineData("")]
        public void InvalidSecondaryPortIsRejected(string port)
            => Assert.False(Inspect(Request(port: port), out _));

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        public void TruncatedRequestFailsClosed(int missingBytes)
        {
            byte[] request = Request();
            Assert.False(Inspect(request.AsSpan(0, request.Length - missingBytes), out _));
        }

        [Fact]
        public void ExtraBytesAfterRequestTerminatorAreRejected()
            => Assert.False(Inspect(Request().Concat(new byte[] { 0x41 }).ToArray(), out _));

        [Fact]
        public void ExcessiveUsernameLengthIsRejected()
            => Assert.False(Inspect(Request(clientUser: new string('a', 257)), out _));

        [Fact]
        public void ExcessiveCommandLengthIsRejected()
            => Assert.False(Inspect(Request(command: new string('x', 1025)), out _));

        [Fact]
        public void EmptyOrControlCharacterUserAndCommandAreRejected()
        {
            Assert.False(Inspect(Request(clientUser: ""), out _));
            Assert.False(Inspect(Request(targetUser: "target\nadmin"), out _));
            Assert.False(Inspect(Request(command: "whoami\nother"), out _));
            Assert.False(Inspect(Request(command: ""), out _));
        }

        [Theory]
        [InlineData(511, 514)]
        [InlineData(1024, 514)]
        [InlineData(700, 512)]
        public void WrongTransportEndpointIsRejected(int sourcePort, int destinationPort)
            => Assert.False(RshRequestInspector.TryInspect(Request(),
                sourcePort, destinationPort, true, true, true, true, true, true, out _));

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        public void MissingIndependentProducerAttestationFailsClosed(int missingFlag)
        {
            bool[] flags = { true, true, true, true, true, true };
            flags[missingFlag] = false;
            Assert.False(RshRequestInspector.TryInspect(Request(), 700, 514,
                flags[0], flags[1], flags[2], flags[3], flags[4], flags[5], out _));
        }

        [Fact]
        public void MissingPortProvenanceFailsClosed()
            => Assert.False(RshRequestInspector.TryInspect(Request(), null, 514,
                true, true, true, true, true, true, out _));

        [Fact]
        public void OutputNeverRetainsUserNamesOrCommand()
        {
            byte[] request = Request(clientUser: "client_sensitive",
                targetUser: "target_sensitive", command: "private_command");
            Assert.True(Inspect(request, out var observation));
            string printed = observation.ToString();
            Assert.DoesNotContain("client_sensitive", printed);
            Assert.DoesNotContain("target_sensitive", printed);
            Assert.DoesNotContain("private_command", printed);
        }

        [Fact]
        public void ConcurrentCallsAreStatelessAndDeterministic()
        {
            byte[] request = Request();
            Parallel.For(0, 128, _ =>
            {
                Assert.True(Inspect(request, out var observation));
                Assert.Equal(0, observation.StandardErrorPort);
            });
        }
    }
