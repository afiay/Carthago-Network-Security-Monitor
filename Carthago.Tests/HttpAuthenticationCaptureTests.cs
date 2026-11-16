// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Net;
using System.Text;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;
public sealed class HttpAuthenticationCaptureTests
{
    private static TrafficRecord Parse(PortablePacketProcessor p, bool reverse, byte flags, uint seq, uint ack, string payload = "", ushort clientPort = 51000)
    {
        var bytes = Encoding.ASCII.GetBytes(payload);
        var frame = new byte[40 + bytes.Length];
        frame[0] = 0x45; frame[8] = 64; frame[9] = 6;
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2,2), (ushort)frame.Length);
        IPAddress.Parse(reverse ? "10.0.0.2" : "10.0.0.1").GetAddressBytes().CopyTo(frame,12);
        IPAddress.Parse(reverse ? "10.0.0.1" : "10.0.0.2").GetAddressBytes().CopyTo(frame,16);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(20,2), (ushort)(reverse ? 80 : clientPort));
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(22,2), (ushort)(reverse ? clientPort : 80));
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(24,4), seq);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(28,4), ack);
        frame[32] = 0x50; frame[33] = flags; bytes.CopyTo(frame,40);
        return Assert.IsType<TrafficRecord>(p.ParseFrame(frame,12));
    }

    [Theory]
    [InlineData("valid", true)]
    [InlineData("wrong-ack", false)]
    [InlineData("wrong-synack", false)]
    [InlineData("retransmit", false)]
    [InlineData("fin", false)]
    [InlineData("ordinary", false)]
    [InlineData("success", false)]
    [InlineData("missing-synack", false)]
    [InlineData("split-request", false)]
    [InlineData("pipeline", false)]
    [InlineData("truncated-response", false)]
    [InlineData("expired", false)]
    [InlineData("boundary", true)]
    [InlineData("reuse", false)]
    public void First_Request_Response_Association(string variant, bool expected)
    {
        var now = new DateTime(2026,11,15,0,0,0,DateTimeKind.Utc);
        var p = new PortablePacketProcessor(() => now);
        Parse(p,false,2,100,0);
        if (variant != "missing-synack") Parse(p,true,0x12,500,variant == "wrong-synack" ? 100u : 101u);
        var request = "GET / HTTP/1.1\r\nHost: camera\r\nAuthorization: Basic " +
            (variant == "ordinary" ? "dTpw" : "YWRtaW46YWRtaW4=") + "\r\n\r\n";
        if (variant == "pipeline") request += "GET /other HTTP/1.1\r\nHost: camera\r\n\r\n";
        var observed = variant == "split-request"
            ? Parse(p,false,0x18,101,501,request[..20])
            : Parse(p,false,0x18,101,501,request);
        if (variant == "split-request") Parse(p,false,0x18,121,501,request[20..]);
        uint end = 101u + (uint)request.Length;
        if (variant == "retransmit") Parse(p,false,0x18,101,501,request);
        if (variant == "fin") Parse(p,false,0x11,end,501);
        if (variant == "reuse") { Parse(p,false,2,900,0); Parse(p,true,0x12,500,901); }
        if (variant == "expired") now = now.AddSeconds(31);
        if (variant == "boundary") now = now.AddSeconds(30);
        var response = Parse(p,true,0x18,501,variant == "wrong-ack" ? end-1 : end,
            variant == "success" ? "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" :
            variant == "truncated-response" ? "HTTP/1.1 401 Unauthorized\r\nContent-Length: 1\r\n\r\n" :
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
        Assert.Equal(expected ? observed.Id : (Guid?)null, response.HttpAuthenticationResponseCorrelationId);
        Assert.Equal(expected ? 401 : (int?)null, response.HttpAuthenticationResponseStatus);
    }

    [Fact]
    public void Capture_Outcome_Is_Not_Restored_From_Json()
    {
        var p = new PortablePacketProcessor(() => new DateTime(2026, 11, 15, 0, 0, 0, DateTimeKind.Utc));
        Parse(p,false,2,100,0);
        Parse(p,true,0x12,500,101);
        const string request = "GET / HTTP/1.1\r\nHost: camera\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n";
        var observed = Parse(p,false,0x18,101,501,request);
        var response = Parse(p,true,0x18,501,101u + (uint)request.Length,
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
        Assert.Equal(observed.Id, response.HttpAuthenticationResponseCorrelationId);
        Assert.Equal(401, response.HttpAuthenticationResponseStatus);
        var json = System.Text.Json.JsonSerializer.Serialize(response);
        Assert.Contains(nameof(TrafficRecord.HttpAuthenticationResponseCorrelationId), json);
        Assert.Contains(nameof(TrafficRecord.HttpAuthenticationResponseStatus), json);
        var imported = System.Text.Json.JsonSerializer.Deserialize<TrafficRecord>(json)!;
        Assert.Null(imported.HttpAuthenticationResponseCorrelationId);
        Assert.Null(imported.HttpAuthenticationResponseStatus);
    }

    [Theory]
    [InlineData(401)]
    [InlineData(403)]
    public void External_Json_Cannot_Assert_Capture_Outcome(int status)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(new
        {
            HttpAuthenticationResponseCorrelationId = Guid.NewGuid(),
            HttpAuthenticationResponseStatus = status,
            HttpBasicDefaultCredentialObserved = true
        });
        var imported = System.Text.Json.JsonSerializer.Deserialize<TrafficRecord>(json)!;
        Assert.Null(imported.HttpAuthenticationResponseCorrelationId);
        Assert.Null(imported.HttpAuthenticationResponseStatus);
        Assert.False(imported.HttpBasicDefaultCredentialObserved);
    }

    [Theory]
    [InlineData(401)]
    [InlineData(403)]
    public void Parallel_Flows_Do_Not_Exchange_Request_Identity(int status)
    {
        var p = new PortablePacketProcessor(() => new DateTime(2026, 11, 15, 0, 0, 0, DateTimeKind.Utc));
        const string request = "GET / HTTP/1.1\r\nHost: camera\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n";
        const ushort other = 51001;
        Parse(p,false,2,100,0);
        Parse(p,true,0x12,500,101);
        var first = Parse(p,false,0x18,101,501,request);
        Parse(p,false,2,100,0,clientPort: other);
        Parse(p,true,0x12,500,101,clientPort: other);
        var second = Parse(p,false,0x18,101,501,request,other);
        Assert.NotEqual(first.Id, second.Id);
        var reply = $"HTTP/1.1 {status} Rejected\r\nContent-Length: 0\r\n\r\n";
        uint end = 101u + (uint)request.Length;
        var b = Parse(p,true,0x18,501,end,reply,other);
        var a = Parse(p,true,0x18,501,end,reply);
        Assert.Equal(second.Id,b.HttpAuthenticationResponseCorrelationId);
        Assert.Equal(first.Id,a.HttpAuthenticationResponseCorrelationId);
        Assert.Equal(status,b.HttpAuthenticationResponseStatus);
        Assert.Equal(status,a.HttpAuthenticationResponseStatus);
        var duplicate = Parse(p,true,0x18,501,end,reply);
        Assert.Null(duplicate.HttpAuthenticationResponseCorrelationId);
        Assert.Null(duplicate.HttpAuthenticationResponseStatus);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Wrapped_Request_Sequence_Requires_Exact_Acknowledgment(bool exact)
    {
        var p = new PortablePacketProcessor(() => new DateTime(2026, 11, 15, 0, 0, 0, DateTimeKind.Utc));
        const uint syn = uint.MaxValue - 20;
        const uint start = syn + 1;
        const string request = "GET / HTTP/1.1\r\nHost: camera\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n";
        Parse(p,false,2,syn,0);
        Parse(p,true,0x12,500,start);
        var observed = Parse(p,false,0x18,start,501,request);
        uint end = unchecked(start + (uint)request.Length);
        Assert.True(end < start);
        var response = Parse(p,true,0x18,501,exact ? end : end-1,
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
        Assert.Equal(exact ? observed.Id : (Guid?)null,response.HttpAuthenticationResponseCorrelationId);
        Assert.Equal(exact ? 401 : (int?)null,response.HttpAuthenticationResponseStatus);
    }
    [Theory]
    [InlineData(401)]
    [InlineData(403)]
    public void Response_Outcome_Does_Not_Rewrite_Request_Evidence(int status)
    {
        var p = new PortablePacketProcessor(() => new DateTime(2026, 11, 15, 0, 0, 0, DateTimeKind.Utc));
        Parse(p,false,2,100,0);
        Parse(p,true,0x12,500,101);
        const string request = "GET / HTTP/1.1\r\nHost: camera\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n";
        var observed = Parse(p,false,0x18,101,501,request);
        Assert.True(observed.HttpBasicDefaultCredentialObserved);
        Assert.Null(observed.HttpAuthenticationResponseCorrelationId);
        Assert.Null(observed.HttpAuthenticationResponseStatus);
        var response = Parse(p,true,0x18,501,101u + (uint)request.Length,
            $"HTTP/1.1 {status} Rejected\r\nContent-Length: 0\r\n\r\n");
        Assert.Equal(observed.Id,response.HttpAuthenticationResponseCorrelationId);
        Assert.Equal(status,response.HttpAuthenticationResponseStatus);
        Assert.False(response.HttpBasicDefaultCredentialObserved);
        Assert.Null(observed.HttpAuthenticationResponseCorrelationId);
        Assert.Null(observed.HttpAuthenticationResponseStatus);
    }
}
