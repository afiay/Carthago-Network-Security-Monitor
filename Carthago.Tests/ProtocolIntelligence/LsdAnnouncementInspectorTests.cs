// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic BEP 14 announcements; hashes and cookies are dummy values.
    // SOURCE CANDIDATE — UNVERIFIED; no tests executed.
    public sealed class LsdAnnouncementInspectorTests
    {
        private const string Hash = "0123456789abcdef0123456789abcdef01234567";
        private static byte[] Announcement(
            string host = "239.192.152.143:6771", string port = "6881",
            string hashes = "Infohash: " + Hash + "\r\n",
            string additional = "")
            => Encoding.ASCII.GetBytes(
                "BT-SEARCH * HTTP/1.1\r\nHost: " + host + "\r\nPort: " + port +
                "\r\n" + hashes + additional + "\r\n");

        private static bool Inspect(ReadOnlySpan<byte> bytes,
            out LsdAnnouncementObservation result)
            => LsdAnnouncementInspector.TryInspect(bytes, 6771,
                true, true, true, true, out result);

        [Theory]
        [InlineData("239.192.152.143:6771")]
        [InlineData("[ff15::efc0:988f]:6771")]
        public void ValidMulticastAnnouncementsReturnOnlyCounts(string host)
        {
            Assert.True(Inspect(Announcement(host: host), out var observation));
            Assert.Equal(6881, observation.AnnouncedPort);
            Assert.Equal(1, observation.InfohashCount);
        }

        [Fact] public void MultipleInfohashesAreCountedWithoutRetention()
        {
            var hashes = "Infohash: " + Hash + "\r\nInfohash: " + Hash + "\r\n";
            Assert.True(Inspect(Announcement(hashes: hashes), out var observation));
            Assert.Equal(2, observation.InfohashCount);
        }

        [Fact] public void CookieAndUnknownExtensionHeaderAreAccepted()
        {
            Assert.True(Inspect(Announcement(additional: "Cookie: synthetic\r\nX-Extension: ok\r\n"), out _));
        }

        [Fact] public void SsdpSearchIsNotLsd()
        {
            var bytes = Announcement();
            bytes[0] = (byte)'M';
            Assert.False(Inspect(bytes, out _));
        }

        [Fact] public void MissingHostFailsClosed()
        {
            var bytes = Encoding.ASCII.GetBytes("BT-SEARCH * HTTP/1.1\r\nPort: 6881\r\nInfohash: " + Hash + "\r\n\r\n");
            Assert.False(Inspect(bytes, out _));
        }

        [Fact] public void MissingInfohashFailsClosed()
        {
            Assert.False(Inspect(Announcement(hashes: ""), out _));
        }

        [Theory]
        [InlineData("abc")]
        [InlineData("0123456789abcdef0123456789abcdef0123456z")]
        public void InvalidHashShapeFailsClosed(string hash)
        {
            Assert.False(Inspect(Announcement(hashes: "Infohash: " + hash + "\r\n"), out _));
        }

        [Theory]
        [InlineData("0")]
        [InlineData("65536")]
        [InlineData("bad")]
        public void InvalidAnnouncedPortFailsClosed(string port)
        {
            Assert.False(Inspect(Announcement(port: port), out _));
        }

        [Fact] public void DuplicateHostHeaderFailsClosed()
        {
            Assert.False(Inspect(Announcement(additional: "Host: 239.192.152.143:6771\r\n"), out _));
        }

        [Fact] public void WrongMulticastHostFailsClosed()
        {
            Assert.False(Inspect(Announcement(host: "example.org:6771"), out _));
        }

        [Fact] public void OversizedDatagramFailsClosed()
        {
            Assert.False(Inspect(Announcement(additional: "X-Pad: " + new string('a', 1400) + "\r\n"), out _));
        }

        [Fact] public void HeaderControlCharactersFailClosed()
        {
            Assert.False(Inspect(Announcement(additional: "X-Extra: control\tbyte\r\n"), out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        public void MissingTrustedBoundaryOrProvenanceFailsClosed(int missingFlag)
        {
            bool[] flags = { true, true, true, true };
            flags[missingFlag] = false;
            Assert.False(LsdAnnouncementInspector.TryInspect(Announcement(), 6771,
                flags[0], flags[1], flags[2], flags[3], out _));
        }

        [Fact] public void WrongUdpDestinationPortFailsClosed()
        {
            Assert.False(LsdAnnouncementInspector.TryInspect(Announcement(), 1900,
                true, true, true, true, out _));
        }

        [Fact] public void MissingCrLfTerminatorFailsClosed()
        {
            var bytes = Announcement();
            Assert.False(Inspect(bytes.AsSpan(0, bytes.Length - 2), out _));
        }

        [Fact] public void TrailingUntrustedBytesFailClosed()
        {
            Assert.False(Inspect(Announcement().Concat(new byte[] { 0x01 }).ToArray(), out _));
        }

        [Fact] public void TooManyInfohashesFailClosed()
        {
            var hashes = string.Concat(Enumerable.Repeat("Infohash: " + Hash + "\r\n", 17));
            Assert.False(Inspect(Announcement(hashes: hashes), out _));
        }

        [Fact] public void InfohashAndCookieNeverAppearInObservation()
        {
            Assert.True(Inspect(Announcement(additional: "Cookie: secret-cookie\r\n"),
                out var observation));
            string printed = observation.ToString();
            Assert.DoesNotContain(Hash, printed);
            Assert.DoesNotContain("secret-cookie", printed);
        }

        [Fact] public void ConcurrentInspectionIsStatelessAndDeterministic()
        {
            var bytes = Announcement();
            Parallel.For(0, 128, _ =>
            {
                Assert.True(Inspect(bytes, out var observation));
                Assert.Equal(1, observation.InfohashCount);
            });
        }
    }
}
