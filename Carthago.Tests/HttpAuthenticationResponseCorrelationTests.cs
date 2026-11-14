// SPDX-License-Identifier: MIT
using System;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests;

public sealed class HttpAuthenticationResponseCorrelationTests
{
    private static readonly DateTime Start = new(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);
    private static readonly byte[] Response = Encoding.ASCII.GetBytes(
        "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");

    [Theory]
    [InlineData(100u, 120u, 0)]
    [InlineData(4294967290u, 14u, 30)]
    public void Exact_Ack_And_Time_Consume_Once(uint seq, uint ack, int seconds)
    {
        var state = new HttpAuthenticationResponseCorrelation();
        var id = Guid.NewGuid();
        Assert.True(state.TryBegin(id, seq, 20, Start));
        Assert.True(state.TryObservePayload(true, true, ack, Start.AddSeconds(seconds),
            Response, out var matched, out int status));
        Assert.Equal(id, matched);
        Assert.Equal(401, status);
        Assert.False(state.TryObservePayload(true, true, ack, Start.AddSeconds(seconds),
            Response, out _, out _));
    }

    [Theory]
    [InlineData(false, true, 120u, 1)]
    [InlineData(true, false, 120u, 1)]
    [InlineData(true, true, 119u, 1)]
    [InlineData(true, true, 121u, 1)]
    [InlineData(true, true, 120u, -1)]
    [InlineData(true, true, 120u, 31)]
    public void Invalid_Association_Consumes_Candidate(bool reverse, bool ackPresent, uint ack, int seconds)
    {
        var state = new HttpAuthenticationResponseCorrelation();
        Assert.True(state.TryBegin(Guid.NewGuid(), 100, 20, Start));
        Assert.False(state.TryObservePayload(reverse, ackPresent, ack, Start.AddSeconds(seconds),
            Response, out var id, out int status));
        Assert.Equal(Guid.Empty, id);
        Assert.Equal(0, status);
        Assert.False(state.TryObservePayload(true, true, 120, Start.AddSeconds(1),
            Response, out _, out _));
    }

    [Fact]
    public void Separate_Connection_And_Second_Request_Cannot_Associate()
    {
        var state = new HttpAuthenticationResponseCorrelation();
        var other = new HttpAuthenticationResponseCorrelation();
        Assert.True(state.TryBegin(Guid.NewGuid(), 100, 20, Start));
        Assert.False(other.TryObservePayload(true, true, 120, Start, Response, out _, out _));
        Assert.False(state.TryBegin(Guid.NewGuid(), 120, 20, Start));
        Assert.False(state.TryObservePayload(true, true, 120, Start, Response, out _, out _));
    }

    [Fact]
    public void Invalidation_And_Unsupported_Response_Do_Not_Leave_Pending_State()
    {
        var state = new HttpAuthenticationResponseCorrelation();
        Assert.True(state.TryBegin(Guid.NewGuid(), 100, 20, Start));
        state.Invalidate();
        Assert.False(state.TryObservePayload(true, true, 120, Start, Response, out _, out _));
        var fresh = new HttpAuthenticationResponseCorrelation();
        Assert.True(fresh.TryBegin(Guid.NewGuid(), 100, 20, Start));
        Assert.False(fresh.TryObservePayload(true, true, 120, Start,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"u8, out _, out _));
        Assert.False(fresh.TryObservePayload(true, true, 120, Start, Response, out _, out _));
    }
}
