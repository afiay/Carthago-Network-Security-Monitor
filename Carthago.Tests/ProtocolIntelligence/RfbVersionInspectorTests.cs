// SPDX-License-Identifier: MIT
using System;
using System.Text;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 6143 plaintext greetings only; no authentication or capture.
    public sealed class RfbVersionInspectorTests
    {
        private static byte[] Version(int minor = 8)
            => Encoding.ASCII.GetBytes($"RFB 003.{minor:000}\n");

        private static bool Inspect(byte[] bytes, out RfbVersionObservation observation,
            bool serverToClient = true, bool complete = true,
            ushort serverPort = 5900, ushort clientPort = 48000)
            => RfbVersionInspector.TryInspect(bytes,
                serverToClient ? serverPort : clientPort,
                serverToClient ? clientPort : serverPort,
                serverToClient, complete, out observation);

        // 1. Published version and both direction envelopes.
        [Theory]
        [InlineData(3)]
        [InlineData(7)]
        [InlineData(8)]
        public void RecognizesPublishedVersionGreetings(int minor)
        {
            Assert.True(Inspect(Version(minor), out var found));
            Assert.Equal(3, found.MajorVersion);
            Assert.Equal(minor, found.MinorVersion);
            Assert.True(found.ServerToClient);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void SupportsAttestedServerAndClientDirections(bool serverToClient)
        {
            Assert.True(Inspect(Version(), out var found, serverToClient));
            Assert.Equal(serverToClient, found.ServerToClient);
        }

        // 2. Cross-protocol, service-port and directional negatives.
        [Fact]
        public void HttpAndRdpLookalikesDoNotPass()
        {
            Assert.False(Inspect(Encoding.ASCII.GetBytes("GET / HTTP/1"), out _));
            Assert.False(Inspect(new byte[] { 3, 0, 0, 11, 6, 0, 0, 0, 0, 0, 0, 0 }, out _));
        }

        [Fact]
        public void WrongServerPortIsNotSufficientEvidence()
            => Assert.False(Inspect(Version(), out _, serverPort: 3389));

        [Fact]
        public void MisattributedDirectionFailsPortBoundary()
            => Assert.False(RfbVersionInspector.TryInspect(
                Version(), 48000, 5900, true, true, out _));

        // 3. Truncation, overlong, malformed, spoofed and unknown versions.
        [Fact]
        public void TruncatedVersionGreetingFailsClosed()
            => Assert.False(Inspect(Version().AsSpan(0, 11).ToArray(), out _));

        [Fact]
        public void AppendedPayloadFailsExactMessageBoundary()
        {
            var longer = Encoding.ASCII.GetBytes("RFB 003.008\npassword");
            Assert.False(Inspect(longer, out _));
        }

        [Fact]
        public void MalformedPrefixAndLineEndingFailClosed()
        {
            var wrong = Version();
            wrong[0] = (byte)'X';
            Assert.False(Inspect(wrong, out _));
            wrong = Version();
            wrong[11] = (byte)'\r';
            Assert.False(Inspect(wrong, out _));
        }

        [Fact]
        public void UnknownOrFutureVersionsAreNotClaimed()
        {
            Assert.False(Inspect(Version(9), out _));
            Assert.False(Inspect(Encoding.ASCII.GetBytes("RFB 004.008\n"), out _));
        }

        // 4. Statelessness and concurrency without session invention.
        [Fact]
        public void ReorderedGreetingsRemainIndependent()
        {
            Assert.True(Inspect(Version(8), out var first));
            Assert.True(Inspect(Version(3), out var second));
            Assert.Equal(8, first.MinorVersion);
            Assert.Equal(3, second.MinorVersion);
        }

        [Fact]
        public void ConcurrentInspectionsAreDeterministic()
        {
            byte[] bytes = Version(7);
            Parallel.For(0, 64, _ =>
                Assert.True(Inspect(bytes, out var found) && found.MinorVersion == 7));
        }

        // 5. Attestation, privacy, encryption and no security-outcome claims.
        [Fact]
        public void UnattestedGreetingFailsClosed()
            => Assert.False(Inspect(Version(), out _, complete: false));

        [Fact]
        public void ObservationContainsOnlyVersionAndDirection()
        {
            Assert.True(Inspect(Version(), out var found));
            Assert.Equal(3, typeof(RfbVersionObservation).GetProperties().Length);
            Assert.DoesNotContain("password", found.ToString(), StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void FailedInputNeverLeaksPartialObservation()
        {
            Assert.False(Inspect(Version(9), out var found));
            Assert.Equal(default(RfbVersionObservation), found);
        }
    }
}
