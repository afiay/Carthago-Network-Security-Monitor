// SPDX-License-Identifier: MIT
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests;

public sealed class HttpAuthenticationResponseInspectorTests
{
    [Theory]
    [InlineData("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n", 401)]
    [InlineData("HTTP/1.0 403 Forbidden\r\ncontent-length: 3\r\n\r\nno!", 403)]
    [InlineData("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"lab\"\r\nContent-Length: 0\r\n\r\n", 401)]
    public void Complete_Explicit_Length_Response(string wire, int expected)
    {
        Assert.True(HttpAuthenticationResponseInspector.TryInspect(Encoding.ASCII.GetBytes(wire), out int status));
        Assert.Equal(expected, status);
    }

    [Theory]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")]
    [InlineData("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n")]
    [InlineData("HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\nx")]
    [InlineData("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\nextra")]
    [InlineData("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n")]
    [InlineData("HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n")]
    [InlineData("HTTP/1.1 401 Unauthorized\r\nContent-Length : 0\r\n\r\n")]
    [InlineData("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n folded\r\n\r\n")]
    [InlineData("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n")]
    [InlineData("HTTP/1.1 401 Unauthorized\r\nContent-Length: 999999999999999999999\r\n\r\n")]
    public void Ambiguous_Or_Unsupported_Response(string wire)
    {
        Assert.False(HttpAuthenticationResponseInspector.TryInspect(Encoding.ASCII.GetBytes(wire), out int status));
        Assert.Equal(0, status);
    }
}
