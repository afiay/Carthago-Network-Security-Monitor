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
public sealed class R578AdvancedAccuracyBatchTests
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
        
        return Assert.IsType<TrafficRecord>(h.ParseFrame(Frame(client, "10.4.1.10", 42001, 6379, 1, 0x18, config ? Request("CONFIG", "SET", "timeout", "30") : Request("PING")), link));
    }
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0) => new(r, Sensitivity.Balanced, Start.AddSeconds(seconds));

    [Fact] public async Task ParsedOrderedRequestsMatch() { var r = new R578_RedisConfigAttemptThenDefaultBasicAdminRule(); Assert.False((await r.EvaluateAsync(At(Redis()))).Matched); Assert.Equal("R578", Assert.Single((await r.EvaluateAsync(At(Http(), 30))).Events).RuleId); }
    [Fact] public async Task ReverseOrderDoesNotMatch() { var r = new R578_RedisConfigAttemptThenDefaultBasicAdminRule(); Assert.False((await r.EvaluateAsync(At(Http()))).Matched); Assert.False((await r.EvaluateAsync(At(Redis(), 1))).Matched); }
    [Fact] public async Task EqualTimestampDoesNotMatch() { var r = new R578_RedisConfigAttemptThenDefaultBasicAdminRule(); Assert.False((await r.EvaluateAsync(At(Redis()))).Matched); Assert.False((await r.EvaluateAsync(At(Http()))).Matched); }
    [Fact] public async Task ExpiredWindowDoesNotMatch() { var r = new R578_RedisConfigAttemptThenDefaultBasicAdminRule(); Assert.False((await r.EvaluateAsync(At(Redis()))).Matched); Assert.False((await r.EvaluateAsync(At(Http(), 121))).Matched); }
    [Fact] public async Task DuplicateIdsDoNotMatch() { var r = new R578_RedisConfigAttemptThenDefaultBasicAdminRule(); var a = Redis(); var b = Http(); b.Id = a.Id; Assert.False((await r.EvaluateAsync(At(a))).Matched); Assert.False((await r.EvaluateAsync(At(b, 1))).Matched); }
    [Fact] public async Task RedisPingIsNotConfigSet() { var r = new R578_RedisConfigAttemptThenDefaultBasicAdminRule(); Assert.False((await r.EvaluateAsync(At(Redis(config: false)))).Matched); Assert.False((await r.EvaluateAsync(At(Http(), 1))).Matched); }
    [Fact] public async Task OrdinaryHttpCredentialsDoNotQualify() { var r = new R578_RedisConfigAttemptThenDefaultBasicAdminRule(); Assert.False((await r.EvaluateAsync(At(Http(credential: "YWRtaW46c3Ryb25n")))).Matched); Assert.False((await r.EvaluateAsync(At(Http(), 1))).Matched); }
    [Fact] public void CandidateShadowRegistryExactlyOnce() { var r = Assert.IsType<R578_RedisConfigAttemptThenDefaultBasicAdminRule>(Assert.Single(RuleRegistry.CreateDefaultRules().Where(x => x.Descriptor.RuleId == "R578"))); Assert.Equal(RulePrecisionMaturity.Candidate, r.PrecisionProfile.Maturity); Assert.Equal(RuleRuntimeMode.Shadow, r.PrecisionProfile.DefaultMode); }
}
