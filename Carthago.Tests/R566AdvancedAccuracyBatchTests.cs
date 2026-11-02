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

public sealed class R566AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 2, 21, 0, 0, DateTimeKind.Utc);
    private const string DefaultBasic = "YWRtaW46YWRtaW4="; // synthetic admin:admin
    private static readonly byte[] Ok = Encoding.ASCII.GetBytes("+OK\r\n");
    private static readonly byte[] Error = Encoding.ASCII.GetBytes("-ERR no permission\r\n");

    private static byte[] Frame(string source, string destination, int sourcePort,
        int destinationPort, uint seq, byte flags, byte[] payload)
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
        frame[24] = (byte)(seq >> 24);
        frame[25] = (byte)(seq >> 16);
        frame[26] = (byte)(seq >> 8);
        frame[27] = (byte)seq;
        frame[32] = 0x50; frame[33] = flags;
        payload.CopyTo(frame, 40);
        return frame;
    }

    private static TrafficRecord Http(string client = "8.8.8.8",
        string server = "10.4.1.10", string path = "/admin",
        string basic = DefaultBasic, string extra = "")
    {
        var request = Encoding.ASCII.GetBytes("GET " + path
            + " HTTP/1.1\r\nHost: gateway.lab.internal\r\nAuthorization: Basic "
            + basic + "\r\n" + extra + "\r\n");
        var record = new PacketHandler().ParseFrame(
            Frame(client, server, 51001, 80, 1, 0x18, request),
            (PacketDotNet.LinkLayers)12);
        return Assert.IsType<TrafficRecord>(record);
    }

    private static byte[] Request(params string[] parts)
    {
        var bytes = new List<byte>();
        bytes.AddRange(Encoding.ASCII.GetBytes("*" + parts.Length + "\r\n"));
        foreach (var part in parts)
        {
            var raw = Encoding.ASCII.GetBytes(part);
            bytes.AddRange(Encoding.ASCII.GetBytes("$" + raw.Length + "\r\n"));
            bytes.AddRange(raw);
            bytes.Add(13); bytes.Add(10);
        }
        return bytes.ToArray();
    }

    private static TrafficRecord Redis(string client = "8.8.8.8",
        string server = "10.4.1.10", int clientPort = 42001,
        byte[]? response = null, bool synAck = true, bool configSet = true)
    {
        var handler = new PacketHandler();
        var link = (PacketDotNet.LinkLayers)12;
        var request = configSet ? Request("CONFIG", "SET", "timeout", "30") : Request("PING");
        Assert.NotNull(handler.ParseFrame(Frame(client, server, clientPort, 6379,
            0, 0x02, Array.Empty<byte>()), link));
        if (synAck)
            Assert.NotNull(handler.ParseFrame(Frame(server, client, 6379, clientPort,
                100, 0x12, Array.Empty<byte>()), link));
        Assert.NotNull(handler.ParseFrame(Frame(client, server, clientPort, 6379,
            1, 0x18, request), link));
        return Assert.IsType<TrafficRecord>(handler.ParseFrame(
            Frame(server, client, 6379, clientPort, 101, 0x18, response ?? Ok), link));
    }

    private static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    [Fact]
    public void ActualProducerFlagsAreInternalAndHaveNoRawSecrets()
    {
        var http = Http();
        var redis = Redis();
        Assert.True(http.HttpBasicDefaultCredentialObserved);
        Assert.Equal("HTTP", http.ApplicationProtocol);
        Assert.Contains("Authorization: [REDACTED]", http.HttpRequestHeaders);
        Assert.DoesNotContain(DefaultBasic, http.HttpRequestHeaders);
        Assert.True(redis.RedisRespConfigSetReplyOkObserved);
        Assert.Equal("redis.resp2", redis.ApplicationProtocol);
        Assert.False(redis.RedisRespConfigSetReplyErrorObserved);
    }

    [Fact]
    public async Task OrderedExactPublicClientAndPrivateServerEmitHighCandidate()
    {
        var rule = new R566_DefaultBasicAdminThenRedisConfigOkRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        var result = await rule.EvaluateAsync(At(Redis(), 30));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R566", evt.RuleId);
        Assert.Equal(SeverityLevel.High, evt.Severity);
        Assert.Equal(1, evt.Count);
        Assert.Equal(120, evt.WindowSeconds);
        Assert.Contains(evt.StructuredEvidence!.Items, item =>
            item.Key == "redis.config_status" && item.Value == "wire_ok_only_not_attested");
    }

    [Fact]
    public async Task BenignNonDefaultAndDuplicateAuthorizationDoNotSeed()
    {
        var rule = new R566_DefaultBasicAdminThenRedisConfigOkRule();
        var ordinary = Http(basic: "YWRtaW46c3Ryb25nLXBhc3M=");
        var duplicate = Http(extra: "Authorization: Bearer synthetic\r\n");
        Assert.False(ordinary.HttpBasicDefaultCredentialObserved);
        Assert.False(duplicate.HttpBasicDefaultCredentialObserved);
        Assert.False((await rule.EvaluateAsync(At(ordinary))).Matched);
        Assert.False((await rule.EvaluateAsync(At(duplicate, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Redis(), 2))).Matched);
    }

    [Fact]
    public async Task NonAdminHttpCannotSeedRedisResponse()
    {
        var rule = new R566_DefaultBasicAdminThenRedisConfigOkRule();
        Assert.False((await rule.EvaluateAsync(At(Http(path: "/status")))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Redis(), 1))).Matched);
    }

    [Fact]
    public async Task RedisErrorAndPingNeverCompleteChain()
    {
        var rule = new R566_DefaultBasicAdminThenRedisConfigOkRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Redis(response: Error), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Redis(configSet: false), 2))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Redis(), 3))).Matched);
    }

    [Fact]
    public async Task RedisWithoutSynAckFailsClosed()
    {
        var reply = Redis(synAck: false);
        Assert.False(reply.RedisRespConfigSetReplyOkObserved);
        var rule = new R566_DefaultBasicAdminThenRedisConfigOkRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(reply, 1))).Matched);
    }

    [Fact]
    public async Task ExactClientAndServerPairMustAgree()
    {
        var rule = new R566_DefaultBasicAdminThenRedisConfigOkRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Redis(client: "1.1.1.1"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Redis(server: "10.4.1.11"), 2))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Redis(), 3))).Matched);
    }

    [Theory]
    [InlineData("192.0.2.7")]
    [InlineData("198.51.100.7")]
    [InlineData("203.0.113.7")]
    [InlineData("100.64.1.7")]
    [InlineData("10.10.1.7")]
    public async Task ReservedOrPrivatePublicPeerCannotQualify(string peer)
    {
        var rule = new R566_DefaultBasicAdminThenRedisConfigOkRule();
        Assert.False((await rule.EvaluateAsync(At(Http(client: peer)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Redis(client: peer), 1))).Matched);
    }

    [Fact]
    public async Task ReverseAndEqualTimeDoNotQualify()
    {
        var reverse = new R566_DefaultBasicAdminThenRedisConfigOkRule();
        Assert.False((await reverse.EvaluateAsync(At(Redis()))).Matched);
        Assert.False((await reverse.EvaluateAsync(At(Http(), 1))).Matched);
        var equal = new R566_DefaultBasicAdminThenRedisConfigOkRule();
        Assert.False((await equal.EvaluateAsync(At(Http()))).Matched);
        Assert.False((await equal.EvaluateAsync(At(Redis()))).Matched);
    }

    [Fact]
    public async Task ExpiredWindowAndOutOfOrderFailClosed()
    {
        var expired = new R566_DefaultBasicAdminThenRedisConfigOkRule();
        Assert.False((await expired.EvaluateAsync(At(Http()))).Matched);
        Assert.False((await expired.EvaluateAsync(At(Redis(), 121))).Matched);
        var order = new R566_DefaultBasicAdminThenRedisConfigOkRule();
        Assert.False((await order.EvaluateAsync(At(Http(), 20))).Matched);
        Assert.False((await order.EvaluateAsync(At(Redis(), 10))).Matched);
    }

    [Fact]
    public async Task DuplicatePacketIdCannotCompletePair()
    {
        var rule = new R566_DefaultBasicAdminThenRedisConfigOkRule();
        var first = Http();
        var second = Redis(); second.Id = first.Id;
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        Assert.False((await rule.EvaluateAsync(At(second, 1))).Matched);
    }

    [Fact]
    public async Task ImportedJsonCannotForgeEitherParserOnlyFlag()
    {
        var fakeHttp = Assert.IsType<TrafficRecord>(JsonSerializer.Deserialize<TrafficRecord>(
            "{\"HttpBasicDefaultCredentialObserved\":true,\"ApplicationProtocol\":\"HTTP\",\"Source\":\"8.8.8.8\",\"Destination\":\"10.4.1.10\"}"));
        var fakeRedis = Assert.IsType<TrafficRecord>(JsonSerializer.Deserialize<TrafficRecord>(
            "{\"RedisRespConfigSetReplyOkObserved\":true,\"ApplicationProtocol\":\"redis.resp2\",\"Source\":\"10.4.1.10\",\"Destination\":\"8.8.8.8\"}"));
        Assert.False(fakeHttp.HttpBasicDefaultCredentialObserved);
        Assert.False(fakeRedis.RedisRespConfigSetReplyOkObserved);
        var rule = new R566_DefaultBasicAdminThenRedisConfigOkRule();
        Assert.False((await rule.EvaluateAsync(At(fakeHttp))).Matched);
        Assert.False((await rule.EvaluateAsync(At(fakeRedis, 1))).Matched);
    }

    [Fact]
    public async Task PortInfoAndContradictoryMetadataCannotForgePair()
    {
        var rule = new R566_DefaultBasicAdminThenRedisConfigOkRule();
        var fakeHttp = Http(); fakeHttp.ApplicationProtocol = "TCP"; fakeHttp.Info = "default password";
        var tlsHttp = Http(); tlsHttp.TlsVersion = "TLS1.3";
        var fakeRedis = Redis(); fakeRedis.ApplicationProtocol = null; fakeRedis.Info = "CONFIG SET +OK";
        var quicRedis = Redis(); quicRedis.IsQuic = true;
        Assert.False((await rule.EvaluateAsync(At(fakeHttp))).Matched);
        Assert.False((await rule.EvaluateAsync(At(tlsHttp, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(fakeRedis, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(quicRedis, 3))).Matched);
    }

    [Fact]
    public async Task CompletedChainConsumesSeedAndCooldownSuppressesNewChain()
    {
        var rule = new R566_DefaultBasicAdminThenRedisConfigOkRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Redis(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Redis(), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Http(), 3))).Matched);
        var result = await rule.EvaluateAsync(At(Redis(), 4));
        Assert.True(result.Suppressed);
        Assert.Empty(result.Events);
    }

    [Fact]
    public async Task ConcurrentDuplicateRedisReplyCannotDoubleEmit()
    {
        var rule = new R566_DefaultBasicAdminThenRedisConfigOkRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        var reply = Redis();
        var results = await Task.WhenAll(
            rule.EvaluateAsync(At(reply, 2)).AsTask(),
            rule.EvaluateAsync(At(reply, 2)).AsTask());
        Assert.Single(results.Where(r => r.Matched));
    }

    [Fact]
    public async Task EvidenceDoesNotCopySecretsOrRedisValues()
    {
        var rule = new R566_DefaultBasicAdminThenRedisConfigOkRule();
        var first = Http(); first.Info = "sensitive-http-marker";
        var second = Redis(); second.Info = "sensitive-redis-marker";
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        var evt = Assert.Single((await rule.EvaluateAsync(At(second, 2))).Events);
        var serialized = JsonSerializer.Serialize(evt);
        Assert.DoesNotContain("sensitive-http-marker", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("sensitive-redis-marker", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(DefaultBasic, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("timeout", serialized, StringComparison.Ordinal);
    }

    [Fact]
    public void ExplicitAdminApprovalOnlyAndRegistryPolicyInvariants()
    {
        var empty = new ApprovedAssetRegistry(new EnvironmentTuningOptions());
        var approved = new ApprovedAssetRegistry(new EnvironmentTuningOptions
        {
            Approved = new ApprovedEnvironmentOptions { AdminHosts = { "8.8.8.8" } }
        });
        Assert.False(R566_DefaultBasicAdminThenRedisConfigOkRule.IsApprovedPair("8.8.8.8", "10.4.1.10", empty));
        Assert.True(R566_DefaultBasicAdminThenRedisConfigOkRule.IsApprovedPair("8.8.8.8", "10.4.1.10", approved));
        Assert.False(R566_DefaultBasicAdminThenRedisConfigOkRule.IsApprovedPair("1.1.1.1", "10.4.1.10", approved));
        var rule = Assert.IsType<R566_DefaultBasicAdminThenRedisConfigOkRule>(
            Assert.Single(RuleRegistry.CreateDefaultRules().Where(r => r.Descriptor.RuleId == "R566")));
        Assert.Equal("Rules.R566.Enabled", rule.Descriptor.ConfigKey);
        Assert.Equal(SeverityLevel.High, rule.Descriptor.DefaultSeverity);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(90, rule.PrecisionProfile.MinimumConfidence);
    }
}
