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

public sealed class R562AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 2, 13, 0, 0, DateTimeKind.Utc);
    private static readonly byte[] Error = Encoding.ASCII.GetBytes("-ERR invalid configuration\r\n");
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

    private static TrafficRecord Exchange(int port = 41001,
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
        Assert.NotNull(handler.ParseFrame(
            Frame(client, server, port, 6379, 1, 0x18, request), link));
        return Assert.IsType<TrafficRecord>(handler.ParseFrame(
            Frame(server, client, 6379, port, 101, 0x18, response ?? Error), link));
    }

    private static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    [Fact]
    public void PacketProducerDistinguishesCorrelatedErrorsAndOk()
    {
        var error = Exchange();
        var ok = Exchange(41002, response: Ok);
        Assert.True(error.RedisRespConfigSetReplyErrorObserved);
        Assert.False(error.RedisRespConfigSetReplyOkObserved);
        Assert.True(ok.RedisRespConfigSetReplyOkObserved);
        Assert.False(ok.RedisRespConfigSetReplyErrorObserved);
        Assert.Equal("redis.resp2", ok.ApplicationProtocol);
        Assert.Equal(6379, ok.SourcePort);
    }

    [Fact]
    public async Task TwoErrorsThenThirdConnectionOkShapeMatches()
    {
        var rule = new R562_RedisConfigSetErrorToOkTransitionRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(41001)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41002), 1))).Matched);
        var result = await rule.EvaluateAsync(At(Exchange(41003, response: Ok), 2));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R562", evt.RuleId);
        Assert.Equal(SeverityLevel.Medium, evt.Severity);
        Assert.Equal(3, evt.Count);
        Assert.Equal(300, evt.WindowSeconds);
    }

    [Fact]
    public async Task ErrorsWithoutOkDoNotMatch()
    {
        var rule = new R562_RedisConfigSetErrorToOkTransitionRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(41001)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41002), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41003), 2))).Matched);
    }

    [Fact]
    public async Task OkBeforeErrorsCannotCompleteSequence()
    {
        var rule = new R562_RedisConfigSetErrorToOkTransitionRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(41001, response: Ok)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41002), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41003), 2))).Matched);
    }

    [Fact]
    public async Task OneErrorAndOkDoNotMeetThreshold()
    {
        var rule = new R562_RedisConfigSetErrorToOkTransitionRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(41001)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41002, response: Ok), 1))).Matched);
    }

    [Fact]
    public async Task SameErrorPortAndSameOkPortCannotInflateDistinctness()
    {
        var rule = new R562_RedisConfigSetErrorToOkTransitionRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(41001)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41001), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41002, response: Ok), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41002), 3))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41002, response: Ok), 4))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Exchange(41003, response: Ok), 5))).Matched);
    }

    [Fact]
    public async Task ClientAndServerPairsRemainIsolated()
    {
        var rule = new R562_RedisConfigSetErrorToOkTransitionRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(41001)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41002), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41003, client: "1.1.1.1", response: Ok), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41004, server: "10.4.0.11", response: Ok), 3))).Matched);
    }

    [Fact]
    public async Task MissingHandshakeMalformedReplyAndUnrelatedCommandFailClosed()
    {
        var rule = new R562_RedisConfigSetErrorToOkTransitionRule();
        var noHandshake = Exchange(41001, synAck: false);
        var malformed = Exchange(41002, response: Encoding.ASCII.GetBytes("-ERR truncated"));
        var unrelated = Exchange(41003, response: Ok, configSet: false);
        Assert.False(noHandshake.RedisRespConfigSetReplyErrorObserved);
        Assert.False(malformed.RedisRespConfigSetReplyErrorObserved);
        Assert.False(unrelated.RedisRespConfigSetReplyOkObserved);
        Assert.False((await rule.EvaluateAsync(At(noHandshake))).Matched);
        Assert.False((await rule.EvaluateAsync(At(malformed, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(unrelated, 2))).Matched);
    }

    [Fact]
    public async Task DuplicateIdCannotCompleteTheTransition()
    {
        var rule = new R562_RedisConfigSetErrorToOkTransitionRule();
        var first = Exchange(41001);
        var second = Exchange(41002);
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        Assert.False((await rule.EvaluateAsync(At(second, 1))).Matched);
        var ok = Exchange(41003, response: Ok);
        ok.Id = second.Id;
        Assert.False((await rule.EvaluateAsync(At(ok, 2))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Exchange(41003, response: Ok), 3))).Matched);
    }

    [Fact]
    public async Task OutOfOrderErrorIsNotCounted()
    {
        var rule = new R562_RedisConfigSetErrorToOkTransitionRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(41001), 20))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41002), 19))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41003, response: Ok), 21))).Matched);
    }

    [Fact]
    public async Task ExpiredErrorsCannotContribute()
    {
        var rule = new R562_RedisConfigSetErrorToOkTransitionRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(41001)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41002), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41003, response: Ok), 303))).Matched);
    }

    [Fact]
    public async Task LateOkBeyondTwoMinuteFollowUpDoesNotMatch()
    {
        var rule = new R562_RedisConfigSetErrorToOkTransitionRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(41001)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41002), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41003, response: Ok), 123))).Matched);
    }

    [Fact]
    public async Task CooldownReturnsSuppressedMatchWithoutDuplicateEvent()
    {
        var rule = new R562_RedisConfigSetErrorToOkTransitionRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(41001)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41002), 1))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Exchange(41003, response: Ok), 2))).Matched);
        var result = await rule.EvaluateAsync(At(Exchange(41004, response: Ok), 3));
        Assert.True(result.Suppressed);
        Assert.Empty(result.Events);
    }

    [Fact]
    public async Task ContradictoryAndInfoOnlyEvidenceFailsClosed()
    {
        var rule = new R562_RedisConfigSetErrorToOkTransitionRule();
        var badApp = Exchange(41001); badApp.ApplicationProtocol = "redis";
        badApp.Info = "CONFIG SET -ERR";
        var tls = Exchange(41002); tls.TlsVersion = "TLS1.3";
        var udp = Exchange(41003, response: Ok); udp.IsTcp = false; udp.IsUdp = true;
        Assert.False((await rule.EvaluateAsync(At(badApp))).Matched);
        Assert.False((await rule.EvaluateAsync(At(tls, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(udp, 2))).Matched);
    }

    [Theory]
    [InlineData("10.4.0.8")]
    [InlineData("192.0.2.5")]
    [InlineData("100.64.1.5")]
    public async Task NonPublicClientCannotMatch(string client)
    {
        var rule = new R562_RedisConfigSetErrorToOkTransitionRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(41001, client: client)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41002, client: client), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41003, client: client, response: Ok), 2))).Matched);
    }

    [Fact]
    public async Task EventRedactsCommandsErrorsAndInfo()
    {
        var rule = new R562_RedisConfigSetErrorToOkTransitionRule();
        var a = Exchange(41001); a.Info = "secret-marker-parameter";
        var b = Exchange(41002); b.Info = "secret-marker-error";
        var c = Exchange(41003, response: Ok); c.Info = "secret-marker-ok";
        Assert.False((await rule.EvaluateAsync(At(a))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, 1))).Matched);
        var evt = Assert.Single((await rule.EvaluateAsync(At(c, 2))).Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains("secret-marker", StringComparison.Ordinal)
                || item.Value.Contains("timeout", StringComparison.Ordinal));
    }

    [Fact]
    public void CandidatePolicyAndRegistryAreExplicit()
    {
        var rule = new R562_RedisConfigSetErrorToOkTransitionRule();
        Assert.Equal("Rules.R562.Enabled", rule.Descriptor.ConfigKey);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(88, rule.PrecisionProfile.MinimumConfidence);
        Assert.Single(RuleRegistry.CreateDefaultRules().Where(r => r.Descriptor.RuleId == "R562"));
    }

    [Fact]
    public void ExplicitApprovedAdminPolicyDoesNotInferUnauthorizedWithoutConfiguration()
    {
        var missing = new ApprovedAssetRegistry(new EnvironmentTuningOptions());
        var approved = new ApprovedAssetRegistry(new EnvironmentTuningOptions
        {
            Approved = new ApprovedEnvironmentOptions { AdminHosts = { "8.8.8.8" } }
        });
        Assert.False(R562_RedisConfigSetErrorToOkTransitionRule.IsApprovedClient("8.8.8.8", missing));
        Assert.True(R562_RedisConfigSetErrorToOkTransitionRule.IsApprovedClient("8.8.8.8", approved));
        Assert.False(R562_RedisConfigSetErrorToOkTransitionRule.IsApprovedClient("1.1.1.1", approved));
    }

    [Fact]
    public async Task ConcurrentDuplicateOkCannotEmitTwice()
    {
        var rule = new R562_RedisConfigSetErrorToOkTransitionRule();
        Assert.False((await rule.EvaluateAsync(At(Exchange(41001)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(41002), 1))).Matched);
        var ok = Exchange(41003, response: Ok);
        var results = await Task.WhenAll(
            rule.EvaluateAsync(At(ok, 2)).AsTask(),
            rule.EvaluateAsync(At(ok, 2)).AsTask());
        Assert.Single(results.Where(r => r.Matched));
    }

    [Fact]
    public void JsonImportedRecordCannotForgeCorrelatedReplyEvidence()
    {
        var record = Assert.IsType<TrafficRecord>(JsonSerializer.Deserialize<TrafficRecord>(
            "{\"ApplicationProtocol\":\"redis.resp2\",\"RedisRespConfigSetReplyErrorObserved\":true,\"RedisRespConfigSetReplyOkObserved\":true}"));
        Assert.False(record.RedisRespConfigSetReplyErrorObserved);
        Assert.False(record.RedisRespConfigSetReplyOkObserved);
    }
}
