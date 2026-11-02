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

    private static byte[] Frame(byte[] payload, int sourcePort, int destinationPort,
        uint sequence, byte flags)
    {
        var frame = new byte[40 + payload.Length];
        frame[0] = 0x45; // IPv4 and 20-byte header
        frame[2] = (byte)(frame.Length >> 8);
        frame[3] = (byte)frame.Length;
        frame[8] = 64;
        frame[9] = 6; // TCP
        var reverse = sourcePort == 6379;
        IPAddress.Parse(reverse ? "10.4.0.10" : "10.4.0.9")
            .GetAddressBytes().CopyTo(frame, 12);
        IPAddress.Parse(reverse ? "10.4.0.9" : "10.4.0.10")
            .GetAddressBytes().CopyTo(frame, 16);
        frame[20] = (byte)(sourcePort >> 8);
        frame[21] = (byte)sourcePort;
        frame[22] = (byte)(destinationPort >> 8);
        frame[23] = (byte)destinationPort;
        frame[24] = (byte)(sequence >> 24);
        frame[25] = (byte)(sequence >> 16);
        frame[26] = (byte)(sequence >> 8);
        frame[27] = (byte)sequence;
        frame[32] = 0x50; // TCP data offset 5 words
        frame[33] = flags;
        payload.CopyTo(frame, 40);
        return frame;
    }

    private static TrafficRecord Parse(byte[] payload, int sourcePort = 40000,
        int destinationPort = 6379, bool witnessedSyn = true, uint payloadSequence = 1)
    {
        var handler = new PacketHandler();
        if (witnessedSyn)
            Assert.NotNull(handler.ParseFrame(
                Frame(Array.Empty<byte>(), sourcePort, destinationPort, 0, 0x02),
                (PacketDotNet.LinkLayers)12));

        var observed = handler.ParseFrame(
            Frame(payload, sourcePort, destinationPort, payloadSequence, 0x18),
            (PacketDotNet.LinkLayers)12);
        return Assert.IsType<TrafficRecord>(observed);
    }

    private static (TrafficRecord Request, TrafficRecord Reply) Exchange(
        byte[] request, byte[] reply, bool witnessedSynAck = true,
        uint replySequence = 101, bool additionalClientPayload = false,
        bool retransmitRequest = false, byte? closingFlags = null,
        bool precedingServerData = false)
    {
        var handler = new PacketHandler();
        var link = (PacketDotNet.LinkLayers)12;

        // Distinct initial sequence numbers prove which direction's first
        // application payload is being admitted; no request bytes are cached.
        Assert.NotNull(handler.ParseFrame(
            Frame(Array.Empty<byte>(), 40000, 6379, 0, 0x02), link));
        if (witnessedSynAck)
            Assert.NotNull(handler.ParseFrame(
                Frame(Array.Empty<byte>(), 6379, 40000, 100, 0x12), link));

        var requestRecord = Assert.IsType<TrafficRecord>(handler.ParseFrame(
            Frame(request, 40000, 6379, 1, 0x18), link));

        if (additionalClientPayload)
            Assert.NotNull(handler.ParseFrame(
                Frame(Request("PING"), 40000, 6379,
                    (uint)(1 + request.Length), 0x18), link));

        if (retransmitRequest)
            Assert.NotNull(handler.ParseFrame(
                Frame(request, 40000, 6379, 1, 0x18), link));

        if (closingFlags.HasValue)
            Assert.NotNull(handler.ParseFrame(
                Frame(Array.Empty<byte>(), 40000, 6379,
                    (uint)(1 + request.Length), closingFlags.Value), link));

        if (precedingServerData)
        {
            var other = Encoding.ASCII.GetBytes("+PONG\r\n");
            Assert.NotNull(handler.ParseFrame(
                Frame(other, 6379, 40000, 101, 0x18), link));
            replySequence = (uint)(101 + other.Length);
        }

        var replyRecord = Assert.IsType<TrafficRecord>(handler.ParseFrame(
            Frame(reply, 6379, 40000, replySequence, 0x18), link));
        return (requestRecord, replyRecord);
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
    public void Midstream_And_Missing_Tcp_Bytes_Are_Not_Trusted_Command_Boundaries()
    {
        var request = Request("CONFIG", "SET", "dir", "/tmp");
        Assert.False(Parse(request, witnessedSyn: false)
            .RedisRespConfigSetRequestObserved);
        Assert.False(Parse(request, payloadSequence: 2)
            .RedisRespConfigSetRequestObserved);
    }

    [Fact]
    public void Strict_Config_Set_First_Command_And_First_Server_Ok_Reply_Correlate()
    {
        const string privateValue = "do-not-retain-this-redis-config-value";
        var (request, reply) = Exchange(
            Request("CONFIG", "SET", "requirepass", privateValue),
            Encoding.ASCII.GetBytes("+OK\r\n"));

        Assert.True(request.RedisRespConfigSetRequestObserved);
        Assert.False(request.RedisRespConfigSetReplyOkObserved);
        Assert.True(reply.RedisRespConfigSetReplyOkObserved);
        Assert.False(reply.RedisRespConfigSetReplyErrorObserved);
        Assert.Equal("redis.resp2", reply.ApplicationProtocol);
        Assert.Null(reply.HttpMethod);
        Assert.Null(reply.HttpUri);
        Assert.Null(reply.HttpHost);
        Assert.Null(reply.HttpRequestHeaders);
        Assert.Equal(6379, reply.SourcePort);
        Assert.Equal("10.4.0.9", reply.Destination);
        Assert.DoesNotContain(privateValue,
            string.Join("|", reply.Info, reply.ApplicationProtocol,
                reply.HttpUserAgent, reply.HttpRequestHeaders, reply.HttpUri));
    }

    [Fact]
    public void Server_Error_Is_Recorded_As_Rejection_Not_Ok()
    {
        var (_, reply) = Exchange(
            Request("CONFIG", "SET", "timeout", "30"),
            Encoding.ASCII.GetBytes("-NOPERM unauthorized CONFIG SET\r\n"));
        Assert.False(reply.RedisRespConfigSetReplyOkObserved);
        Assert.True(reply.RedisRespConfigSetReplyErrorObserved);
        Assert.Equal("redis.resp2", reply.ApplicationProtocol);
        Assert.Null(reply.HttpMethod);
        Assert.Null(reply.HttpUri);
        Assert.Null(reply.HttpHost);
        Assert.Null(reply.HttpRequestHeaders);
        Assert.DoesNotContain("NOPERM", reply.Info ?? string.Empty);
    }

    [Fact]
    public void Http_Request_On_Redis_Port_Remains_Http_When_Not_Resp2()
    {
        var http = Encoding.ASCII.GetBytes(
            "GET /health HTTP/1.1\r\nHost: redis.example\r\n\r\n");
        var observed = Parse(http, destinationPort: 6379);
        Assert.False(observed.RedisRespConfigSetRequestObserved);
        Assert.Equal("HTTP", observed.ApplicationProtocol);
        Assert.Equal("GET", observed.HttpMethod);
    }

    [Theory]
    [InlineData("+PONG\r\n")]
    [InlineData(":1\r\n")]
    [InlineData("+OK\r\n+OK\r\n")]
    [InlineData("+OK\r")]
    public void Unsupported_Coalesced_Or_Truncated_Server_Replies_Fail_Closed(string wire)
    {
        var (_, reply) = Exchange(
            Request("CONFIG", "SET", "timeout", "30"),
            Encoding.ASCII.GetBytes(wire));
        Assert.False(reply.RedisRespConfigSetReplyOkObserved);
        Assert.False(reply.RedisRespConfigSetReplyErrorObserved);
    }

    [Fact]
    public void Missing_SynAck_Or_Gapped_Server_Sequence_Cannot_Confirm_The_Request()
    {
        var req = Request("CONFIG", "SET", "timeout", "30");
        var reply = Encoding.ASCII.GetBytes("+OK\r\n");
        Assert.False(Exchange(req, reply, witnessedSynAck: false)
            .Reply.RedisRespConfigSetReplyOkObserved);
        Assert.False(Exchange(req, reply, replySequence: 102)
            .Reply.RedisRespConfigSetReplyOkObserved);
    }

    [Fact]
    public void Pipelining_Extra_Client_Data_And_Request_Retransmits_Clear_Correlation()
    {
        var req = Request("CONFIG", "SET", "timeout", "30");
        var reply = Encoding.ASCII.GetBytes("+OK\r\n");
        Assert.False(Exchange(req.Concat(Request("PING")).ToArray(), reply)
            .Reply.RedisRespConfigSetReplyOkObserved);
        Assert.False(Exchange(req, reply, additionalClientPayload: true)
            .Reply.RedisRespConfigSetReplyOkObserved);
        Assert.False(Exchange(req, reply, retransmitRequest: true)
            .Reply.RedisRespConfigSetReplyOkObserved);
    }

    [Theory]
    [InlineData((byte)0x11)] // FIN + ACK
    [InlineData((byte)0x14)] // RST + ACK
    public void Connection_Termination_Cancels_Outstanding_Config_Set(byte flags)
    {
        var (_, reply) = Exchange(Request("CONFIG", "SET", "timeout", "30"),
            Encoding.ASCII.GetBytes("+OK\r\n"), closingFlags: flags);
        Assert.False(reply.RedisRespConfigSetReplyOkObserved);
    }

    [Fact]
    public void Prior_Server_Data_Consumes_The_Only_Eligible_Response()
    {
        var (_, reply) = Exchange(Request("CONFIG", "SET", "timeout", "30"),
            Encoding.ASCII.GetBytes("+OK\r\n"), precedingServerData: true);
        Assert.False(reply.RedisRespConfigSetReplyOkObserved);
    }

    [Fact]
    public void Redis_Reply_Correlation_Has_A_Thirty_Second_Deadline()
    {
        var start = new DateTime(2026, 11, 2, 12, 0, 0, DateTimeKind.Utc);
        Assert.True(PacketHandler.IsWithinRedisReplyWindow(start, start));
        Assert.True(PacketHandler.IsWithinRedisReplyWindow(start,
            start.AddSeconds(30)));
        Assert.False(PacketHandler.IsWithinRedisReplyWindow(start,
            start.AddSeconds(31)));
        Assert.False(PacketHandler.IsWithinRedisReplyWindow(start,
            start.AddMilliseconds(-1)));
        Assert.False(PacketHandler.IsWithinRedisReplyWindow(default,
            start));
    }

    [Fact]
    public void Request_Other_Than_Config_Set_Does_Not_Correlate_Ok_As_Write()
    {
        var (_, reply) = Exchange(Request("CONFIG", "GET", "timeout"),
            Encoding.ASCII.GetBytes("+OK\r\n"));
        Assert.False(reply.RedisRespConfigSetReplyOkObserved);
    }

    [Fact]
    public async Task Correlated_Server_Reply_And_AdminHosts_Policy_Remain_NonAlerting()
    {
        var (_, reply) = Exchange(Request("CONFIG", "SET", "timeout", "30"),
            Encoding.ASCII.GetBytes("+OK\r\n"));
        Assert.True(reply.RedisRespConfigSetReplyOkObserved);

        var missing = new Carthago.Services.EnvironmentTuning.ApprovedAssetRegistry(
            new Carthago.Services.EnvironmentTuning.EnvironmentTuningOptions());
        var approved = new Carthago.Services.EnvironmentTuning.ApprovedAssetRegistry(
            new Carthago.Services.EnvironmentTuning.EnvironmentTuningOptions
            {
                Approved = new Carthago.Services.EnvironmentTuning.ApprovedEnvironmentOptions
                {
                    AdminHosts = { "10.4.0.9" }
                }
            });
        var other = new Carthago.Services.EnvironmentTuning.ApprovedAssetRegistry(
            new Carthago.Services.EnvironmentTuning.EnvironmentTuningOptions
            {
                Approved = new Carthago.Services.EnvironmentTuning.ApprovedEnvironmentOptions
                {
                    AdminHosts = { "10.4.0.7" }
                }
            });

        Assert.Equal(RedisConfigSetClientAssessment.PolicyUnconfigured,
            R437_RedisCONFIGSETIndicatorRule.AssessCorrelatedClient(reply, missing));
        Assert.Equal(RedisConfigSetClientAssessment.ApprovedAdminHost,
            R437_RedisCONFIGSETIndicatorRule.AssessCorrelatedClient(reply, approved));
        Assert.Equal(RedisConfigSetClientAssessment.UnapprovedClient,
            R437_RedisCONFIGSETIndicatorRule.AssessCorrelatedClient(reply, other));

        // A wire-correlated +OK cannot be promoted to an alert by default.
        var result = await new R437_RedisCONFIGSETIndicatorRule().EvaluateAsync(
            new RuleEvaluationContext(reply, Sensitivity.Balanced, DateTime.UtcNow));
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
    }

    [Fact]
    public async Task Rejected_Config_Set_Reply_Is_Not_Security_Detection()
    {
        var (_, reply) = Exchange(Request("CONFIG", "SET", "timeout", "30"),
            Encoding.ASCII.GetBytes("-NOPERM no permission\r\n"));
        var result = await new R437_RedisCONFIGSETIndicatorRule().EvaluateAsync(
            new RuleEvaluationContext(reply, Sensitivity.Balanced, DateTime.UtcNow));
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        Assert.Contains(result.NoMatchReasons,
            reason => reason.Code == "REDIS_CONFIG_SET_SERVER_REJECTED");
    }

    [Fact]
    public void Missing_Correlated_Endpoints_Cannot_Be_Classified_As_Unapproved()
    {
        var registry = new Carthago.Services.EnvironmentTuning.ApprovedAssetRegistry(
            new Carthago.Services.EnvironmentTuning.EnvironmentTuningOptions
            {
                Approved = new Carthago.Services.EnvironmentTuning.ApprovedEnvironmentOptions
                {
                    AdminHosts = { "10.4.0.9" }
                }
            });

        var missingDestination = new TrafficRecord
        {
            Protocol = "TCP", IsTcp = true, Source = "10.4.0.10",
            SourcePort = 6379
        };
        Assert.Equal(RedisConfigSetClientAssessment.MissingEndpoints,
            R437_RedisCONFIGSETIndicatorRule.AssessCorrelatedClient(
                missingDestination, registry));
    }

    [Fact]
    public void Reused_Tcp_Tuple_Cannot_Use_Stale_SynAck_As_New_Server_Provenance()
    {
        var handler = new PacketHandler();
        var link = (PacketDotNet.LinkLayers)12;
        var request = Request("CONFIG", "SET", "timeout", "30");

        Assert.NotNull(handler.ParseFrame(
            Frame(Array.Empty<byte>(), 40000, 6379, 0, 0x02), link));
        Assert.NotNull(handler.ParseFrame(
            Frame(Array.Empty<byte>(), 6379, 40000, 100, 0x12), link));

        // New connection reuses both ports; no SYN-ACK for the new session.
        Assert.NotNull(handler.ParseFrame(
            Frame(Array.Empty<byte>(), 40000, 6379, 200, 0x02), link));
        var observedRequest = Assert.IsType<TrafficRecord>(handler.ParseFrame(
            Frame(request, 40000, 6379, 201, 0x18), link));
        Assert.True(observedRequest.RedisRespConfigSetRequestObserved);

        var reply = Assert.IsType<TrafficRecord>(handler.ParseFrame(
            Frame(Encoding.ASCII.GetBytes("+OK\r\n"),
                6379, 40000, 101, 0x18), link));
        Assert.False(reply.RedisRespConfigSetReplyOkObserved);
    }

    [Fact]
    public void Imported_Json_Cannot_Forge_Capture_Only_Provenance()
    {
        var record = Assert.IsType<TrafficRecord>(JsonSerializer.Deserialize<TrafficRecord>(
            "{\"ApplicationProtocol\":\"redis.resp2\",\"RedisRespConfigSetRequestObserved\":true,\"RedisRespConfigSetReplyOkObserved\":true,\"RedisRespConfigSetReplyErrorObserved\":true}"));
        Assert.False(record.RedisRespConfigSetRequestObserved);
        Assert.False(record.RedisRespConfigSetReplyOkObserved);
        Assert.False(record.RedisRespConfigSetReplyErrorObserved);
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
