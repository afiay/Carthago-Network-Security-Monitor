// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.EnvironmentTuning;
using Xunit;

namespace Carthago.Tests;

public sealed class R564AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 2, 20, 0, 0, DateTimeKind.Utc);
    private static readonly byte[] Ok = Encoding.ASCII.GetBytes("+OK\r\n");
    private static readonly byte[] Error = Encoding.ASCII.GetBytes("-ERR permission denied\r\n");

    private static byte[] Request(params string[] parts)
    {
        var bytes = new List<byte>();
        bytes.AddRange(Encoding.ASCII.GetBytes("*" + parts.Length + "\r\n"));
        foreach (var part in parts)
        {
            var raw = Encoding.ASCII.GetBytes(part);
            bytes.AddRange(Encoding.ASCII.GetBytes("$" + raw.Length + "\r\n"));
            bytes.AddRange(raw);
            bytes.Add(13);
            bytes.Add(10);
        }
        return bytes.ToArray();
    }

    private static byte[] Frame(string source, string destination, int sourcePort,
        int destinationPort, uint sequence, byte flags, byte[] payload)
    {
        var frame = new byte[40 + payload.Length];
        frame[0] = 0x45;
        frame[2] = (byte)(frame.Length >> 8);
        frame[3] = (byte)frame.Length;
        frame[8] = 64; frame[9] = 6;
        IPAddress.Parse(source).GetAddressBytes().CopyTo(frame, 12);
        IPAddress.Parse(destination).GetAddressBytes().CopyTo(frame, 16);
        frame[20] = (byte)(sourcePort >> 8);
        frame[21] = (byte)sourcePort;
        frame[22] = (byte)(destinationPort >> 8);
        frame[23] = (byte)destinationPort;
        frame[24] = (byte)(sequence >> 24);
        frame[25] = (byte)(sequence >> 16);
        frame[26] = (byte)(sequence >> 8);
        frame[27] = (byte)sequence;
        frame[32] = 0x50;
        frame[33] = flags;
        payload.CopyTo(frame, 40);
        return frame;
    }

    private static TrafficRecord Exchange(string client = "8.8.8.8",
        string server = "10.4.1.10", int port = 41001,
        byte[]? response = null, bool synAck = true, bool configSet = true)
    {
        var handler = new PacketHandler();
        var link = (PacketDotNet.LinkLayers)12;
        var request = configSet
            ? Request("CONFIG", "SET", "timeout", "30")
            : Request("PING");
        Assert.NotNull(handler.ParseFrame(
            Frame(client, server, port, 6379, 0, 0x02, Array.Empty<byte>()), link));
        if (synAck)
            Assert.NotNull(handler.ParseFrame(
                Frame(server, client, 6379, port, 100, 0x12, Array.Empty<byte>()), link));
        Assert.NotNull(handler.ParseFrame(
            Frame(client, server, port, 6379, 1, 0x18, request), link));
        return Assert.IsType<TrafficRecord>(handler.ParseFrame(
            Frame(server, client, 6379, port, 101, 0x18, response ?? Ok), link));
    }

    private static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    [Fact]
    public void PacketHandlerProducesCorrelatedOkAndRejectsUnrelatedResponses()
    {
        var ok = Exchange();
        var error = Exchange(response: Error);
        var ping = Exchange(configSet: false);
        Assert.True(ok.RedisRespConfigSetReplyOkObserved);
        Assert.False(ok.RedisRespConfigSetReplyErrorObserved);
        Assert.False(ok.RedisRespConfigSetRequestObserved);
        Assert.Equal("redis.resp2", ok.ApplicationProtocol);
        Assert.Equal(6379, ok.SourcePort);
        Assert.True(error.RedisRespConfigSetReplyErrorObserved);
        Assert.False(error.RedisRespConfigSetReplyOkObserved);
        Assert.False(ping.RedisRespConfigSetReplyOkObserved);
    }

    [Fact]
    public async Task TwoPrivateSubnetsDistinctPortsOnePublicClientMatchHighShadowCandidate()
    {
        var rule = new R564_ExternalRedisConfigSetOkSubnetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange()))).Matched);
        var result = await rule.EvaluateAsync(At(Exchange(server: "10.5.2.20", port: 41002), 2));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R564", evt.RuleId);
        Assert.Equal(SeverityLevel.High, evt.Severity);
        Assert.Equal(2, evt.Count);
        Assert.Equal(300, evt.WindowSeconds);
        Assert.Contains(evt.StructuredEvidence!.Items, item =>
            item.Key == "network.direction" && item.Value == "private_server_to_public_client");
    }

    [Fact]
    public async Task SamePrivateSubnetDifferentServersNeverMeetsThreshold()
    {
        var rule = new R564_ExternalRedisConfigSetOkSubnetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(server: "10.4.1.11", port: 41002), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(server: "10.4.1.12", port: 41003), 3))).Matched);
    }

    [Fact]
    public async Task DifferentPublicClientsCannotCombineReplies()
    {
        var rule = new R564_ExternalRedisConfigSetOkSubnetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(client: "1.1.1.1",
            server: "10.5.2.20", port: 41002), 2))).Matched);
    }

    [Fact]
    public async Task ErrorAndOkRepliesCannotSatisfyTwoOkThreshold()
    {
        var rule = new R564_ExternalRedisConfigSetOkSubnetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(response: Error)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(server: "10.5.2.20", port: 41002), 1))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Exchange(server: "10.6.3.20", port: 41003), 2))).Matched);
    }

    [Fact]
    public async Task MissingSynAckAndUnrelatedPingFailClosed()
    {
        var rule = new R564_ExternalRedisConfigSetOkSubnetFanoutRule();
        var missingHandshake = Exchange(synAck: false);
        var ping = Exchange(server: "10.5.2.20", port: 41002, configSet: false);
        Assert.False(missingHandshake.RedisRespConfigSetReplyOkObserved);
        Assert.False(ping.RedisRespConfigSetReplyOkObserved);
        Assert.False((await rule.EvaluateAsync(At(missingHandshake))).Matched);
        Assert.False((await rule.EvaluateAsync(At(ping, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(server: "10.6.3.20", port: 41003), 2))).Matched);
    }

    [Fact]
    public async Task DistinctClientPortsRequiredEvenAcrossPrivateSubnets()
    {
        var rule = new R564_ExternalRedisConfigSetOkSubnetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(server: "10.5.2.20", port: 41001), 1))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Exchange(server: "10.6.3.20", port: 41002), 2))).Matched);
    }

    [Fact]
    public async Task DuplicatePacketIdCannotCompleteThreshold()
    {
        var rule = new R564_ExternalRedisConfigSetOkSubnetFanoutRule();
        var first = Exchange();
        var second = Exchange(server: "10.5.2.20", port: 41002);
        second.Id = first.Id;
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        Assert.False((await rule.EvaluateAsync(At(second, 1))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Exchange(server: "10.6.3.20", port: 41003), 2))).Matched);
    }

    [Fact]
    public async Task OutOfOrderAndEqualTimestampsFailClosed()
    {
        var backwards = new R564_ExternalRedisConfigSetOkSubnetFanoutRule();
        Assert.False((await backwards.EvaluateAsync(At(Exchange(), 10))).Matched);
        Assert.False((await backwards.EvaluateAsync(At(Exchange(server: "10.5.2.20", port: 41002), 9))).Matched);
        var equal = new R564_ExternalRedisConfigSetOkSubnetFanoutRule();
        Assert.False((await equal.EvaluateAsync(At(Exchange()))).Matched);
        Assert.False((await equal.EvaluateAsync(At(Exchange(server: "10.5.2.20", port: 41002)))).Matched);
    }

    [Fact]
    public async Task WindowExpiryDoesNotCarryOldSubnetForward()
    {
        var rule = new R564_ExternalRedisConfigSetOkSubnetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(server: "10.5.2.20", port: 41002), 301))).Matched);
    }

    [Fact]
    public async Task FreshSecondPairDuringCooldownReturnsSuppressed()
    {
        var rule = new R564_ExternalRedisConfigSetOkSubnetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange()))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Exchange(server: "10.5.2.20", port: 41002), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(server: "10.6.3.20", port: 41003), 2))).Matched);
        var suppressed = await rule.EvaluateAsync(At(Exchange(server: "10.7.4.20", port: 41004), 3));
        Assert.True(suppressed.Suppressed);
        Assert.Empty(suppressed.Events);
    }

    [Fact]
    public async Task ConcurrentSamePacketCannotDoubleEmit()
    {
        var rule = new R564_ExternalRedisConfigSetOkSubnetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange()))).Matched);
        var same = Exchange(server: "10.5.2.20", port: 41002);
        var results = await Task.WhenAll(
            rule.EvaluateAsync(At(same, 2)).AsTask(),
            rule.EvaluateAsync(At(same, 2)).AsTask());
        Assert.Single(results.Where(result => result.Matched));
    }

    [Fact]
    public async Task InfoOnlyPortOnlyAndContradictoryTlsCannotForgeMatch()
    {
        var rule = new R564_ExternalRedisConfigSetOkSubnetFanoutRule();
        var info = Exchange(); info.ApplicationProtocol = null; info.Info = "CONFIG SET +OK";
        var tls = Exchange(server: "10.5.2.20", port: 41002); tls.TlsVersion = "TLS1.3";
        var quic = Exchange(server: "10.6.3.20", port: 41003); quic.IsQuic = true;
        Assert.False((await rule.EvaluateAsync(At(info))).Matched);
        Assert.False((await rule.EvaluateAsync(At(tls, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(quic, 2))).Matched);
    }

    [Fact]
    public async Task ImportedJsonCannotClaimPacketHandlerOnlyOkFlag()
    {
        var forged = Assert.IsType<TrafficRecord>(JsonSerializer.Deserialize<TrafficRecord>(
            "{\"ApplicationProtocol\":\"redis.resp2\",\"RedisRespConfigSetReplyOkObserved\":true,\"Source\":\"10.4.1.10\",\"Destination\":\"8.8.8.8\"}"));
        Assert.False(forged.RedisRespConfigSetReplyOkObserved);
        var rule = new R564_ExternalRedisConfigSetOkSubnetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(forged))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(server: "10.5.2.20", port: 41002), 1))).Matched);
    }

    [Theory]
    [InlineData("192.0.2.7")]
    [InlineData("198.51.100.7")]
    [InlineData("203.0.113.7")]
    [InlineData("100.64.1.7")]
    [InlineData("10.20.1.7")]
    public async Task ReservedOrPrivateClientCannotQualify(string client)
    {
        var rule = new R564_ExternalRedisConfigSetOkSubnetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(client: client)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(client: client,
            server: "10.5.2.20", port: 41002), 1))).Matched);
    }

    [Fact]
    public async Task EventNeverCopiesCommandValuesInfoOrRawReply()
    {
        var rule = new R564_ExternalRedisConfigSetOkSubnetFanoutRule();
        var first = Exchange(); first.Info = "first-secret-marker";
        var second = Exchange(server: "10.5.2.20", port: 41002);
        second.Info = "second-secret-marker";
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        var evt = Assert.Single((await rule.EvaluateAsync(At(second, 2))).Events);
        var json = JsonSerializer.Serialize(evt);
        Assert.DoesNotContain("secret-marker", json, StringComparison.Ordinal);
        Assert.DoesNotContain("timeout", json, StringComparison.Ordinal);
        Assert.DoesNotContain("first-secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.Contains(evt.StructuredEvidence!.Items, item =>
            item.Key == "redis.reply_shape" && item.Value == "resp2.ok_after_correlated_config_set");
    }

    [Fact]
    public void ExplicitApprovedAdminPolicyIsNotImplicitAuthorization()
    {
        var empty = new ApprovedAssetRegistry(new EnvironmentTuningOptions());
        var approved = new ApprovedAssetRegistry(new EnvironmentTuningOptions
        {
            Approved = new ApprovedEnvironmentOptions { AdminHosts = { "8.8.8.8" } }
        });
        Assert.False(R564_ExternalRedisConfigSetOkSubnetFanoutRule.IsApprovedClient("8.8.8.8", empty));
        Assert.True(R564_ExternalRedisConfigSetOkSubnetFanoutRule.IsApprovedClient("8.8.8.8", approved));
        Assert.False(R564_ExternalRedisConfigSetOkSubnetFanoutRule.IsApprovedClient("1.1.1.1", approved));
    }

    [Fact]
    public void UniqueRegistryCandidateShadowAndConfidenceArePreserved()
    {
        var rule = Assert.IsType<R564_ExternalRedisConfigSetOkSubnetFanoutRule>(
            Assert.Single(RuleRegistry.CreateDefaultRules()
                .Where(r => r.Descriptor.RuleId == "R564")));
        Assert.Equal("Rules.R564.Enabled", rule.Descriptor.ConfigKey);
        Assert.Equal(SeverityLevel.High, rule.Descriptor.DefaultSeverity);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(90, rule.PrecisionProfile.MinimumConfidence);
    }
}
