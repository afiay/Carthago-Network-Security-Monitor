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
    private static TrafficRecord Parse(PortablePacketProcessor p, bool reverse, byte flags, uint seq, uint ack, string payload = "")
    {
        var bytes = Encoding.ASCII.GetBytes(payload);
        var frame = new byte[40 + bytes.Length];
        frame[0] = 0x45; frame[8] = 64; frame[9] = 6;
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2,2), (ushort)frame.Length);
        IPAddress.Parse(reverse ? "10.0.0.2" : "10.0.0.1").GetAddressBytes().CopyTo(frame,12);
        IPAddress.Parse(reverse ? "10.0.0.1" : "10.0.0.2").GetAddressBytes().CopyTo(frame,16);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(20,2), (ushort)(reverse ? 80 : 51000));
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(22,2), (ushort)(reverse ? 51000 : 80));
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
    public void First_Request_Response_Association(string variant, bool expected)
    {
        var p = new PortablePacketProcessor(() => new DateTime(2026,11,15,0,0,0,DateTimeKind.Utc));
        Parse(p,false,2,100,0);
        Parse(p,true,0x12,500,variant == "wrong-synack" ? 100u : 101u);
        var request = "GET / HTTP/1.1\r\nHost: camera\r\nAuthorization: Basic " +
            (variant == "ordinary" ? "dTpw" : "YWRtaW46YWRtaW4=") + "\r\n\r\n";
        var observed = Parse(p,false,0x18,101,501,request);
        uint end = 101u + (uint)request.Length;
        if (variant == "retransmit") Parse(p,false,0x18,101,501,request);
        if (variant == "fin") Parse(p,false,0x11,end,501);
        var response = Parse(p,true,0x18,501,variant == "wrong-ack" ? end-1 : end,
            variant == "success" ? "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" :
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
        Assert.Equal(expected ? observed.Id : (Guid?)null, response.HttpAuthenticationResponseCorrelationId);
        Assert.Equal(expected ? 401 : (int?)null, response.HttpAuthenticationResponseStatus);
    }
}
