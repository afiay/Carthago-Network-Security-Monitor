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
using Xunit;
namespace Carthago.Tests;
public sealed class R567AdvancedAccuracyBatchTests
{
    private static readonly DateTime Start = new(2026, 11, 3, 0, 0, 0, DateTimeKind.Utc);
    private static byte[] Frame(string source, string destination, int sp, int dp, uint seq, byte flags, byte[] payload)
    {
        var b = new byte[40 + payload.Length]; b[0] = 0x45; b[2] = (byte)(b.Length >> 8); b[3] = (byte)b.Length;
        b[8] = 64; b[9] = 6;
        IPAddress.Parse(source).GetAddressBytes().CopyTo(b, 12); IPAddress.Parse(destination).GetAddressBytes().CopyTo(b, 16);
        b[20] = (byte)(sp >> 8); b[21] = (byte)sp; b[22] = (byte)(dp >> 8); b[23] = (byte)dp;
        b[24] = (byte)(seq >> 24); b[25] = (byte)(seq >> 16); b[26] = (byte)(seq >> 8); b[27] = (byte)seq;
        b[32] = 0x50; b[33] = flags; payload.CopyTo(b, 40); return b;
    }
    private static TrafficRecord Http(string client = "8.8.8.8", string path = "/admin", string credential = "YWRtaW46YWRtaW4=")
    {
        var payload = Encoding.ASCII.GetBytes("GET " + path + " HTTP/1.1\r\nHost: gateway.lab.internal\r\nAuthorization: Basic " + credential + "\r\n\r\n");
        return Assert.IsType<TrafficRecord>(new PacketHandler().ParseFrame(Frame(client, "10.4.1.10", 51001, 80, 1, 0x18, payload), (PacketDotNet.LinkLayers)12));
    }
    private static byte[] Request(params string[] parts)
    {
        var b = new List<byte>(); b.AddRange(Encoding.ASCII.GetBytes("*" + parts.Length + "\r\n"));
        foreach (var p in parts) { var x = Encoding.ASCII.GetBytes(p); b.AddRange(Encoding.ASCII.GetBytes("$" + x.Length + "\r\n")); b.AddRange(x); b.Add(13); b.Add(10); }
        return b.ToArray();
    }
    private static TrafficRecord Redis(string client = "8.8.8.8", byte[]? response = null, bool handshake = true, bool config = true)
    {
        var h = new PacketHandler(); var link = (PacketDotNet.LinkLayers)12;
        Assert.NotNull(h.ParseFrame(Frame(client, "10.4.1.10", 42001, 6379, 0, 0x02, Array.Empty<byte>()), link));
        if (handshake) Assert.NotNull(h.ParseFrame(Frame("10.4.1.10", client, 6379, 42001, 100, 0x12, Array.Empty<byte>()), link));
        Assert.NotNull(h.ParseFrame(Frame(client, "10.4.1.10", 42001, 6379, 1, 0x18, config ? Request("CONFIG", "SET", "timeout", "30") : Request("PING")), link));
        return Assert.IsType<TrafficRecord>(h.ParseFrame(Frame("10.4.1.10", client, 6379, 42001, 101, 0x18, response ?? Encoding.ASCII.GetBytes("-ERR no permission\r\n")), link));
    }
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0) => new(r, Sensitivity.Balanced, Start.AddSeconds(seconds));
    [Fact] public async Task CorrelatedDeniedConfigAfterDefaultAdminAttemptMatches()
    {
        var rule = new R567_DefaultBasicAdminThenRedisConfigDeniedRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        var redis = Redis(); Assert.True(redis.RedisRespConfigSetReplyErrorObserved);
        var result = await rule.EvaluateAsync(At(redis, 30)); Assert.True(result.Matched);
        Assert.Equal("R567", Assert.Single(result.Events).RuleId);
    }
    [Fact] public async Task SuccessfulRedisReplyDoesNotMatchDeniedOutcome()
    {
        var rule = new R567_DefaultBasicAdminThenRedisConfigDeniedRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Redis(response: Encoding.ASCII.GetBytes("+OK\r\n")), 1))).Matched);
    }
    [Fact] public async Task BenignCredentialAndNonAdminPathDoNotSeed()
    {
        foreach (var seed in new[] { Http(credential: "YWRtaW46c3Ryb25n"), Http(path: "/status") })
        {
            var rule = new R567_DefaultBasicAdminThenRedisConfigDeniedRule();
            Assert.False((await rule.EvaluateAsync(At(seed))).Matched);
            Assert.False((await rule.EvaluateAsync(At(Redis(), 1))).Matched);
        }
    }
    [Fact] public async Task HandshakeAndPeerIdentityAreRequired()
    {
        var rule = new R567_DefaultBasicAdminThenRedisConfigDeniedRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Redis(handshake: false), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Redis(client: "1.1.1.1"), 2))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Redis(), 3))).Matched);
    }
    [Fact] public async Task WindowAndDuplicateIdsFailClosed()
    {
        var late = new R567_DefaultBasicAdminThenRedisConfigDeniedRule();
        Assert.False((await late.EvaluateAsync(At(Http()))).Matched);
        Assert.False((await late.EvaluateAsync(At(Redis(), 121))).Matched);
        var duplicate = new R567_DefaultBasicAdminThenRedisConfigDeniedRule();
        var http = Http(); var redis = Redis(); redis.Id = http.Id;
        Assert.False((await duplicate.EvaluateAsync(At(http))).Matched);
        Assert.False((await duplicate.EvaluateAsync(At(redis, 1))).Matched);
    }
    [Fact] public async Task SpoofedJsonAndContradictoryMetadataFailClosed()
    {
        var fake = Assert.IsType<TrafficRecord>(JsonSerializer.Deserialize<TrafficRecord>("{\"RedisRespConfigSetReplyErrorObserved\":true,\"ApplicationProtocol\":\"redis.resp2\"}"));
        Assert.False(fake.RedisRespConfigSetReplyErrorObserved);
        var rule = new R567_DefaultBasicAdminThenRedisConfigDeniedRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(fake, 1))).Matched);
        var bad = Redis(); bad.TlsVersion = "TLS1.3";
        Assert.False((await rule.EvaluateAsync(At(bad, 2))).Matched);
    }
    [Fact] public async Task EvidenceIsPrivacySafeAndRegistryHasCandidateShadow()
    {
        var rule = Assert.IsType<R567_DefaultBasicAdminThenRedisConfigDeniedRule>(
            Assert.Single(RuleRegistry.CreateDefaultRules().Where(x => x.Descriptor.RuleId == "R567")));
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        var redis = Redis(); redis.Info = "private-secret-marker";
        var evt = Assert.Single((await rule.EvaluateAsync(At(redis, 1))).Events);
        Assert.DoesNotContain("private-secret-marker", JsonSerializer.Serialize(evt), StringComparison.Ordinal);
    }
}
