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
public sealed class R572AdvancedAccuracyBatchTests
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
    private static TrafficRecord Ftp(string command = "STOR synthetic.bin\r\n", string client = "8.8.8.8")
        => Assert.IsType<TrafficRecord>(new PacketHandler().ParseFrame(Frame("10.4.1.10", client, 51002, 21, 1, 0x18, Encoding.ASCII.GetBytes(command)), (PacketDotNet.LinkLayers)12));
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0) => new(r, Sensitivity.Balanced, Start.AddSeconds(seconds));

    [Fact] public async Task ParserBackedPositive() { var r = new R572_RedisErrorThenFtpUploadRule(); Assert.False((await r.EvaluateAsync(At(Redis()))).Matched); Assert.Equal("R572", Assert.Single((await r.EvaluateAsync(At(Ftp(), 10))).Events).RuleId); }
    [Fact] public async Task ReverseOrderRejected() { var r = new R572_RedisErrorThenFtpUploadRule(); Assert.False((await r.EvaluateAsync(At(Ftp()))).Matched); Assert.False((await r.EvaluateAsync(At(Redis(), 1))).Matched); }
    [Fact] public async Task EqualTimestampRejected() { var r = new R572_RedisErrorThenFtpUploadRule(); Assert.False((await r.EvaluateAsync(At(Redis()))).Matched); Assert.False((await r.EvaluateAsync(At(Ftp()))).Matched); }
    [Fact] public async Task ExpiredWindowRejected() { var r = new R572_RedisErrorThenFtpUploadRule(); Assert.False((await r.EvaluateAsync(At(Redis()))).Matched); Assert.False((await r.EvaluateAsync(At(Ftp(), 121))).Matched); }
    [Fact] public async Task DuplicateIdsRejected() { var r = new R572_RedisErrorThenFtpUploadRule(); var a = Redis(); var b = Ftp(); b.Id = a.Id; Assert.False((await r.EvaluateAsync(At(a))).Matched); Assert.False((await r.EvaluateAsync(At(b, 1))).Matched); }
    [Fact] public async Task FtpReadRejected() { var r = new R572_RedisErrorThenFtpUploadRule(); Assert.False((await r.EvaluateAsync(At(Ftp(command: "RETR synthetic.bin\r\n")))).Matched); Assert.False((await r.EvaluateAsync(At(Ftp(), 1))).Matched); }
    [Fact] public async Task OppositeRedisStatusRejected() { var r = new R572_RedisErrorThenFtpUploadRule(); Assert.False((await r.EvaluateAsync(At(Redis(response: Encoding.ASCII.GetBytes("+OK\\r\\n")))).Matched); Assert.False((await r.EvaluateAsync(At(Ftp(), 1))).Matched); }
    [Fact] public void CandidateShadowRegisteredOnce() { var r = Assert.IsType<R572_RedisErrorThenFtpUploadRule>(Assert.Single(RuleRegistry.CreateDefaultRules().Where(x => x.Descriptor.RuleId == "R572"))); Assert.Equal(RulePrecisionMaturity.Candidate, r.PrecisionProfile.Maturity); Assert.Equal(RuleRuntimeMode.Shadow, r.PrecisionProfile.DefaultMode); }
}
