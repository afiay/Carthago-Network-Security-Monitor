// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Net;
using System.Text;
using Carthago.Models;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;
public sealed class R601HeaderCaptureTests
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

    internal static TrafficRecord Request(string method, string uri, string headers)
    {
        var p = new PortablePacketProcessor(() => DateTime.UtcNow);
        Parse(p,false,2,100,0);
        Parse(p,true,0x12,500,101);
        return Parse(p,false,0x18,101,501,method + " " + uri + " HTTP/1.1\r\n" + headers);
    }

    [Theory]
    [InlineData("POST", "/tunnel.jsp?cmd=connect", "Host: camera\r\n\r\n", true)]
    [InlineData("POST", "/tunnel.jsp?cmd=connect", "Host: camera\r\nUser-Agent:\r\n\r\n", false)]
    [InlineData("POST", "/tunnel.jsp?cmd=connect", "Host: camera\r\nReferer:\r\n\r\n", false)]
    [InlineData("POST", "/tunnel.jsp?cmd=connect", "Host: camera\r\n", false)]
    [InlineData("POST", "/tunnel.jsp?cmd=normal", "Host: camera\r\n\r\n", false)]
    [InlineData("GET", "/tunnel.jsp?cmd=connect", "Host: camera\r\n\r\n", false)]
    public async System.Threading.Tasks.Task Capture_To_Windows_And_Core(string method, string uri, string headers, bool expected)
    {
        var record = Request(method, uri, headers);
        var context = new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UnixEpoch);
        var observation = new PortableR601Detector().Evaluate(context.Packet, out _);
        var actual = await new R601_ReGeorgHeaderlessControlQueryRequestRule().EvaluateAsync(context);
        Assert.Equal(expected, observation == WebSignatureObservation.Match);
        Assert.Equal(expected, actual.Matched);
        if (expected) Assert.Equal("R601", Assert.Single(actual.Events).RuleId);
        else Assert.Empty(actual.Events);
    }

    [Theory]
    [InlineData("Host: camera\r\n\r\n", true, false, false)]
    [InlineData("Host: camera\r\nUser-Agent:\r\nReferer:\r\n\r\n", true, true, true)]
    [InlineData("Host: camera\r\nUser-Agent: partial", false, false, false)]
    [InlineData("Host: camera\r\nUser-Agent : bad\r\n\r\n", false, false, false)]
    public void First_Request_Header_Evidence(string headers, bool complete, bool agent, bool referer)
    {
        var p = new PortablePacketProcessor(() => DateTime.UtcNow);
        Parse(p,false,2,100,0);
        Parse(p,true,0x12,500,101);
        var record = Parse(p,false,0x18,101,501,"POST /control HTTP/1.1\r\n" + headers);
        Assert.Equal(complete, record.HttpCompleteRequestHeadersObserved);
        Assert.Equal(agent, record.HttpUserAgentHeaderObserved);
        Assert.Equal(referer, record.HttpRefererHeaderObserved);
        var imported = System.Text.Json.JsonSerializer.Deserialize<TrafficRecord>(
            System.Text.Json.JsonSerializer.Serialize(record))!;
        Assert.False(imported.HttpCompleteRequestHeadersObserved);
        Assert.False(imported.HttpUserAgentHeaderObserved);
        Assert.False(imported.HttpRefererHeaderObserved);
    }
}
