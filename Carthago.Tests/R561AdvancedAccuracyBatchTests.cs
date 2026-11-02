// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed.
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
using Xunit;

namespace Carthago.Tests;

public sealed class R561AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 2, 12, 0, 0, DateTimeKind.Utc);
    private static readonly byte[] Error = Encoding.ASCII.GetBytes("-NOPERM no permission\r\n");
    private static readonly byte[] Ok = Encoding.ASCII.GetBytes("+OK\r\n");

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

    private static byte[] Frame(string source, string destination,
        int sourcePort, int destinationPort, uint sequence, byte flags, byte[] payload)
    {
        var frame = new byte[40 + payload.Length];
        frame[0] = 0x45;
        frame[2] = (byte)(frame.Length >> 8);
        frame[3] = (byte)frame.Length;
        frame[8] = 64;
        frame[9] = 6;
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

    private static TrafficRecord Exchange(int port = 40001,
        string client = "8.8.8.8", string server = "10.4.0.10",
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
        var requestRecord = Assert.IsType<TrafficRecord>(handler.ParseFrame(
            Frame(client, server, port, 6379, 1, 0x18, request), link));
        Assert.Equal(configSet, requestRecord.RedisRespConfigSetRequestObserved);
        return Assert.IsType<TrafficRecord>(handler.ParseFrame(
            Frame(server, client, 6379, port, 101, 0x18, response ?? Error), link));
    }

    private static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    [Fact]
    public void RealPacketProducerDistinguishesCorrelatedErrorFromOk()
    {
        var rejected = Exchange();
        Assert.True(rejected.RedisRespConfigSetReplyErrorObserved);
        Assert.False(rejected.RedisRespConfigSetReplyOkObserved);
        Assert.Equal("redis.resp2", rejected.ApplicationProtocol);
        Assert.Equal(6379, rejected.SourcePort);
        Assert.Equal(40001, rejected.DestinationPort);
        var accepted = Exchange(response: Ok);
        Assert.True(accepted.RedisRespConfigSetReplyOkObserved);
        Assert.False(accepted.RedisRespConfigSetReplyErrorObserved);
    }

    [Fact]
    public async Task ThreeDistinctConnectionsProduceOneCandidate()
    {
        var rule = new R561_RedisConfigSetRejectedReplyBurstRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(40001)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(40002), 1))).Matched);
        var result = await rule.EvaluateAsync(At(Exchange(40003), 2));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R561", evt.RuleId);
        Assert.Equal(SeverityLevel.Medium, evt.Severity);
        Assert.Equal(3, evt.Count);
        Assert.Equal(300, evt.WindowSeconds);
    }

    [Fact]
    public async Task OneOrTwoErrorsDoNotMeetThreshold()
    {
        var rule = new R561_RedisConfigSetRejectedReplyBurstRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(40001)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(40002), 1))).Matched);
    }

    [Fact]
    public async Task SuccessfulAndUncorrelatedRepliesDoNotContribute()
    {
        var rule = new R561_RedisConfigSetRejectedReplyBurstRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(40001, response: Ok)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(40002, configSet: false), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(40003), 2))).Matched);
    }

    [Fact]
    public async Task MissingHandshakeAndMalformedReplyFailClosed()
    {
        var rule = new R561_RedisConfigSetRejectedReplyBurstRule();
        var missing = Exchange(40001, synAck: false);
        var malformed = Exchange(40002, response: Encoding.ASCII.GetBytes("-ERR incomplete"));
        Assert.False(missing.RedisRespConfigSetReplyErrorObserved);
        Assert.False(malformed.RedisRespConfigSetReplyErrorObserved);
        Assert.False((await rule.EvaluateAsync(At(missing))).Matched);
        Assert.False((await rule.EvaluateAsync(At(malformed, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(40003), 2))).Matched);
    }

    [Fact]
    public async Task DifferentClientsAndServersRemainIsolated()
    {
        var rule = new R561_RedisConfigSetRejectedReplyBurstRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(40001)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(40002), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(40003, client: "1.1.1.1"), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(40004, server: "10.4.0.11"), 3))).Matched);
    }

    [Fact]
    public async Task RepeatedPortAndDuplicatePacketIdCannotInflateCount()
    {
        var rule = new R561_RedisConfigSetRejectedReplyBurstRule();
        var a = Exchange(40001);
        var b = Exchange(40002);
        Assert.False((await rule.EvaluateAsync(At(a))).Matched);
        Assert.False((await rule.EvaluateAsync(At(a, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(40001), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, 3))).Matched);
        var c = Exchange(40003); c.Id = b.Id;
        Assert.False((await rule.EvaluateAsync(At(c, 4))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Exchange(40003), 5))).Matched);
    }

    [Fact]
    public async Task OutOfOrderAndExpiredObservationsDoNotMatch()
    {
        var rule = new R561_RedisConfigSetRejectedReplyBurstRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(40001), 20))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(40002), 19))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(40003), 321))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(40004), 322))).Matched);
    }

    [Fact]
    public async Task CooldownProducesSuppressedMatch()
    {
        var rule = new R561_RedisConfigSetRejectedReplyBurstRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(40001)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(40002), 1))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Exchange(40003), 2))).Matched);
        var result = await rule.EvaluateAsync(At(Exchange(40004), 3));
        Assert.True(result.Suppressed);
        Assert.Empty(result.Events);
    }

    [Fact]
    public async Task ForgedLabelsAndContradictoryTransportCannotMatch()
    {
        var rule = new R561_RedisConfigSetRejectedReplyBurstRule();
        var infoOnly = Exchange(40001);
        infoOnly.ApplicationProtocol = "redis";
        infoOnly.Info = "redis CONFIG SET -NOPERM";
        var tls = Exchange(40002); tls.TlsVersion = "TLS1.3";
        var udp = Exchange(40003); udp.IsTcp = false; udp.IsUdp = true;
        Assert.False((await rule.EvaluateAsync(At(infoOnly))).Matched);
        Assert.False((await rule.EvaluateAsync(At(tls, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(udp, 2))).Matched);
    }

    [Theory]
    [InlineData("192.0.2.10")]
    [InlineData("10.4.0.9")]
    [InlineData("100.64.1.10")]
    public async Task NonPublicClientNeverMatches(string client)
    {
        var rule = new R561_RedisConfigSetRejectedReplyBurstRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(40001, client: client)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(40002, client: client), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(40003, client: client), 2))).Matched);
    }

    [Fact]
    public async Task StructuredEvidenceDoesNotExposeRedisParametersOrErrorText()
    {
        var rule = new R561_RedisConfigSetRejectedReplyBurstRule();
        var a = Exchange(40001); a.Info = "private-parameter=secret-marker";
        var b = Exchange(40002); b.Info = "NOPERM secret-marker";
        var c = Exchange(40003); c.Info = "secret-marker";
        Assert.False((await rule.EvaluateAsync(At(a))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, 1))).Matched);
        var evt = Assert.Single((await rule.EvaluateAsync(At(c, 2))).Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains("secret-marker", StringComparison.Ordinal)
                || item.Value.Contains("NOPERM", StringComparison.Ordinal));
    }

    [Fact]
    public void CandidateShadowPolicyAndRegistryAreExplicit()
    {
        var rule = new R561_RedisConfigSetRejectedReplyBurstRule();
        Assert.Equal("Rules.R561.Enabled", rule.Descriptor.ConfigKey);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(86, rule.PrecisionProfile.MinimumConfidence);
        Assert.Single(RuleRegistry.CreateDefaultRules().Where(r => r.Descriptor.RuleId == "R561"));
    }

    [Fact]
    public void ApprovedAdminHostPolicyIsExplicitWithoutInferringUnauthorizedStatus()
    {
        var missing = new Carthago.Services.EnvironmentTuning.ApprovedAssetRegistry(
            new Carthago.Services.EnvironmentTuning.EnvironmentTuningOptions());
        var approved = new Carthago.Services.EnvironmentTuning.ApprovedAssetRegistry(
            new Carthago.Services.EnvironmentTuning.EnvironmentTuningOptions
            {
                Approved = new Carthago.Services.EnvironmentTuning.ApprovedEnvironmentOptions
                {
                    AdminHosts = { "8.8.8.8" }
                }
            });
        var unrelated = new Carthago.Services.EnvironmentTuning.ApprovedAssetRegistry(
            new Carthago.Services.EnvironmentTuning.EnvironmentTuningOptions
            {
                Approved = new Carthago.Services.EnvironmentTuning.ApprovedEnvironmentOptions
                {
                    AdminHosts = { "1.1.1.1" }
                }
            });
        Assert.False(R561_RedisConfigSetRejectedReplyBurstRule.IsApprovedClient("8.8.8.8", missing));
        Assert.True(R561_RedisConfigSetRejectedReplyBurstRule.IsApprovedClient("8.8.8.8", approved));
        Assert.False(R561_RedisConfigSetRejectedReplyBurstRule.IsApprovedClient("8.8.8.8", unrelated));
    }

    [Fact]
    public async Task ConcurrentThirdReplyCannotEmitTwice()
    {
        var rule = new R561_RedisConfigSetRejectedReplyBurstRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(40001)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(40002), 1))).Matched);
        var third = Exchange(40003);
        var results = await Task.WhenAll(
            rule.EvaluateAsync(At(third, 2)).AsTask(),
            rule.EvaluateAsync(At(third, 2)).AsTask());
        Assert.Single(results.Where(r => r.Matched));
    }

    [Fact]
    public void JsonImportCannotForgeInternalReplyEvidence()
    {
        var record = Assert.IsType<TrafficRecord>(JsonSerializer.Deserialize<TrafficRecord>(
            "{\"ApplicationProtocol\":\"redis.resp2\",\"RedisRespConfigSetReplyErrorObserved\":true}"));
        Assert.False(record.RedisRespConfigSetReplyErrorObserved);
    }
}
