// SPDX-License-Identifier: MIT
// GA Redis evidence producer — SOURCE CANDIDATE — UNVERIFIED.
// Synthetic raw IPv4/TCP frames, not external capture or confirmed Redis outcomes.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class RedisRespCaptureIntegrationTests
{
    private static byte[] Request(params string[] parts)
    {
        var bytes = new List<byte>();
        bytes.AddRange(Encoding.ASCII.GetBytes("*" + parts.Length + "\r\n"));
        foreach (var part in parts)
        {
            var raw = Encoding.UTF8.GetBytes(part);
            bytes.AddRange(Encoding.ASCII.GetBytes("$" + raw.Length + "\r\n"));
            bytes.AddRange(raw);
            bytes.Add(13);
            bytes.Add(10);
        }
        return bytes.ToArray();
    }

    private static TrafficRecord Parse(byte[] payload, int sourcePort = 40000, int destinationPort = 6379)
    {
        var frame = new byte[40 + payload.Length];
        frame[0] = 0x45; // IPv4 and 20-byte header
        frame[2] = (byte)(frame.Length >> 8);
        frame[3] = (byte)frame.Length;
        frame[8] = 64;
        frame[9] = 6; // TCP
        IPAddress.Parse("10.4.0.9").GetAddressBytes().CopyTo(frame, 12);
        IPAddress.Parse("10.4.0.10").GetAddressBytes().CopyTo(frame, 16);
        frame[20] = (byte)(sourcePort >> 8);
        frame[21] = (byte)sourcePort;
        frame[22] = (byte)(destinationPort >> 8);
        frame[23] = (byte)destinationPort;
        frame[32] = 0x50; // TCP data offset 5 words
        frame[33] = 0x18; // PSH, ACK
        payload.CopyTo(frame, 40);

        var observed = new PacketHandler().ParseFrame(frame, (PacketDotNet.LinkLayers)12);
        return Assert.IsType<TrafficRecord>(observed);
    }

    [Fact]
    public void Complete_Config_Set_Request_Produces_Privacy_Safe_Capture_Attribution()
    {
        const string value = "private-value-should-not-appear";
        const string name = "requirepass";
        var record = Parse(Request("CONFIG", "SET", name, value));

        Assert.True(record.RedisRespConfigSetRequestObserved);
        Assert.Equal("redis.resp2", record.ApplicationProtocol);
        Assert.Equal(6379, record.DestinationPort);
        Assert.True(record.IsTcp);
        var presentation = string.Join("|", record.Info, record.ApplicationProtocol,
            record.HttpUri, record.HttpRequestHeaders, record.HttpUserAgent);
        Assert.DoesNotContain(name, presentation);
        Assert.DoesNotContain(value, presentation);
    }

    [Theory]
    [InlineData("CONFIG", "GET", "dir")]
    [InlineData("CONFIG", "SET", "dir")]
    [InlineData("PING", "SET", "dir")]
    [InlineData("SET", "CONFIG", "SET")]
    [InlineData("CONFIG", "GET", "SET")]
    public void Valid_Non_Config_Set_Commands_Do_Not_Assert_Write_Provenance(
        string first, string second, string third)
    {
        var observed = Parse(Request(first, second, third));
        Assert.False(observed.RedisRespConfigSetRequestObserved);
        Assert.Equal("redis.resp2", observed.ApplicationProtocol);
    }

    [Fact]
    public void Server_Reply_And_Wrong_Port_Cannot_Assert_Redis_Config_Set()
    {
        var body = Request("CONFIG", "SET", "timeout", "30");
        Assert.False(Parse(body, sourcePort: 6379, destinationPort: 40000)
            .RedisRespConfigSetRequestObserved);
        Assert.False(Parse(body, destinationPort: 16379)
            .RedisRespConfigSetRequestObserved);
        Assert.False(Parse(Encoding.ASCII.GetBytes("+OK\r\n"))
            .RedisRespConfigSetRequestObserved);
    }

    [Fact]
    public void Truncated_Command_And_Coalesced_Different_Command_Are_Not_Promoted()
    {
        var body = Request("CONFIG", "SET", "timeout", "30");
        Assert.False(Parse(body.Take(body.Length - 1).ToArray())
            .RedisRespConfigSetRequestObserved);
        var first = Request("GET", "key");
        var combined = first.Concat(body).ToArray();
        Assert.False(Parse(combined).RedisRespConfigSetRequestObserved);
    }

    [Fact]
    public void Imported_Json_Cannot_Forge_Capture_Only_Provenance()
    {
        var record = JsonSerializer.Deserialize<TrafficRecord>(
            "{\"ApplicationProtocol\":\"redis.resp2\",\"RedisRespConfigSetRequestObserved\":true}");
        Assert.NotNull(record);
        Assert.False(record.RedisRespConfigSetRequestObserved);
    }

    [Fact]
    public async Task Parsed_Request_Remains_R437_NoMatch_Without_Trusted_Response_And_Authorization()
    {
        var record = Parse(Request("CONFIG", "SET", "timeout", "30"));
        Assert.True(record.RedisRespConfigSetRequestObserved);

        var result = await new R437_RedisCONFIGSETIndicatorRule().EvaluateAsync(
            new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        Assert.Contains(result.NoMatchReasons,
            reason => reason.Code == "REDIS_RESP_CONFIG_SET_UNAVAILABLE");
    }
}
