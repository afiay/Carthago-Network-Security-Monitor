// SPDX-License-Identifier: MIT
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class HttpConnectRequestInspectorTests
    {
        [Fact]
        public void AcceptsCompleteConnectAuthorityWithMatchingHost()
        {
            var bytes = Encoding.ASCII.GetBytes("CONNECT example.org:8443 HTTP/1.1\r\nHost: example.org:8443\r\n\r\n");
            Assert.True(HttpConnectRequestInspector.TryInspect(bytes, true, out var host, out var port));
            Assert.Equal("example.org", host);
            Assert.Equal(8443, port);
        }

        [Theory]
        [InlineData("CONNECT example.org:8443 HTTP/1.1\r\nHost: other.org:8443\r\n\r\n")]
        [InlineData("CONNECT example.org:8443 HTTP/1.1\r\nHost: example.org:8443\r\nContent-Length: 1\r\n\r\n")]
        [InlineData("CONNECT example.org:8443 HTTP/1.1\r\nHost: example.org:8443\r\nHost: example.org:8443\r\n\r\n")]
        [InlineData("GET example.org:8443 HTTP/1.1\r\nHost: example.org:8443\r\n\r\n")]
        [InlineData("CONNECT example.org:8443 HTTP/1.1\r\nHost: example.org:8443\r\n")]
        public void RejectsMalformedOrAmbiguousRequests(string raw)
        {
            Assert.False(HttpConnectRequestInspector.TryInspect(Encoding.ASCII.GetBytes(raw), true, out _, out _));
        }

        [Fact]
        public void RequiresExplicitCompletePlaintextInput()
        {
            var bytes = Encoding.ASCII.GetBytes("CONNECT example.org:8443 HTTP/1.1\r\nHost: example.org:8443\r\n\r\n");
            Assert.False(HttpConnectRequestInspector.TryInspect(bytes, false, out _, out _));
        }
    }
}
