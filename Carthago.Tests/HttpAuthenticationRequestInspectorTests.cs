// SPDX-License-Identifier: MIT
using System;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests;

public sealed class HttpAuthenticationRequestInspectorTests
{
    [Fact]
    public void Authentication_Primitives_Are_Owned_By_Portable_Core()
    {
        var core = typeof(Carthago.Models.TrafficRecord).Assembly;
        Assert.Same(core, typeof(HttpAuthenticationRequestInspector).Assembly);
        Assert.Same(core, typeof(HttpAuthenticationResponseInspector).Assembly);
        Assert.Same(core, typeof(HttpAuthenticationResponseCorrelation).Assembly);
    }

    [Theory]
    [InlineData("GET / HTTP/1.1\r\nHost: camera\r\n\r\n", true)]
    [InlineData("GET /login HTTP/1.1\r\nHost: camera\r\nContent-Length: 0\r\n\r\n", true)]
    [InlineData("HEAD / HTTP/1.1\r\nHost: camera\r\n\r\n", false)]
    [InlineData("GET / HTTP/1.1\r\nHost: camera\r\n\r\nx", false)]
    [InlineData("GET / HTTP/1.1\r\nHost: camera\r\nContent-Length: 1\r\n\r\n", false)]
    [InlineData("GET / HTTP/1.1\r\nHost: camera\r\nTransfer-Encoding: chunked\r\n\r\n", false)]
    [InlineData("GET / HTTP/1.1\r\nHost: camera\r\nHost: other\r\n\r\n", false)]
    [InlineData("GET / HTTP/1.1\r\nHost: camera\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n", false)]
    [InlineData("GET / HTTP/1.1\r\nHost: camera\r\n", false)]
    [InlineData("GET / HTTP/1.1\r\nHost: camera local\r\n\r\n", false)]
    [InlineData("GET / HTTP/1.1\r\nHost: camera\tlocal\r\n\r\n", false)]
    [InlineData("GET / HTTP/1.1\r\nHost: camera\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nauthorization: Basic dTpw\r\n\r\n", false)]
    [InlineData("GET / HTTP/1.1\r\nHost: camera\r\nAuthorization: \t\r\n\r\n", false)]
    [InlineData("GET / HTTP/1.1\r\nHost: camera\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n", true)]
    public void Framing_Gates_Association(string request, bool expected)
    {
        var payload = Encoding.ASCII.GetBytes(request);
        Assert.Equal(expected, HttpAuthenticationRequestInspector.IsCompleteGet(payload));
        var state = new HttpAuthenticationResponseCorrelation();
        var now = new DateTime(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);
        var id = Guid.NewGuid();
        Assert.Equal(expected, state.TryBeginFramedGet(id, 100, payload, now));
        Assert.Equal(expected, state.TryObservePayload(true, true, (uint)(100 + payload.Length),
            now, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"u8,
            out var matched, out _));
        Assert.Equal(expected ? id : Guid.Empty, matched);
    }
}
