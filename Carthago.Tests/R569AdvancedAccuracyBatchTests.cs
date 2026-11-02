// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.
using System;
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

public sealed class R569AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 2, 13, 0, 0, DateTimeKind.Utc);
    private const string SyntheticBasic = "YWRtaW46YWRtaW4="; // synthetic admin:admin

    private static TrafficRecord Packet(string source, string destination,
        int sourcePort, int destinationPort, string request)
    {
        var bytes = Encoding.ASCII.GetBytes(request);
        var frame = new byte[40 + bytes.Length];
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
        frame[32] = 0x50; frame[33] = 0x18;
        bytes.CopyTo(frame, 40);
        var record = new PacketHandler().ParseFrame(frame, (PacketDotNet.LinkLayers)12);
        Assert.NotNull(record);
        return record!;
    }

    private static TrafficRecord Http(string publicPeer = "8.8.8.8", string internalHost = "10.42.1.20",
        string path = "/admin", string basic = SyntheticBasic, string extra = "")
        => Packet(publicPeer, internalHost, 51001, 80,
            "GET " + path + " HTTP/1.1\r\nHost: gateway.lab.internal\r\n"
            + "Authorization: Basic " + basic + "\r\n" + extra + "\r\n");

    private static TrafficRecord Ftp(string internalHost = "10.42.1.20", string publicPeer = "8.8.8.8",
        string command = "STOR synthetic.bin\r\n", int port = 21)
        => Packet(internalHost, publicPeer, 51002, port, command);

    private static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));


    [Fact] public void ProducerParsesFtpAndRedactedDefaultHttp()
    {
        Assert.Equal("ftp.stor", Ftp().ApplicationProtocol);
        Assert.True(Http().HttpBasicDefaultCredentialObserved);
        Assert.Contains("Authorization: [REDACTED]", Http().HttpRequestHeaders);
    }
    [Fact] public async Task FtpBeforeHttpMatchesExactEndpoints()
    {
        var rule = new R569_FtpUploadAttemptThenDefaultBasicAdminRule();
        Assert.False((await rule.EvaluateAsync(At(Ftp()))).Matched);
        var result = await rule.EvaluateAsync(At(Http(), 20));
        Assert.True(result.Matched);
        Assert.Equal("R569", Assert.Single(result.Events).RuleId);
    }
    [Fact] public async Task ReverseOrderAndEqualTimeNeverMatch()
    {
        var reverse = new R569_FtpUploadAttemptThenDefaultBasicAdminRule();
        Assert.False((await reverse.EvaluateAsync(At(Http()))).Matched);
        Assert.False((await reverse.EvaluateAsync(At(Ftp(), 1))).Matched);
        var equal = new R569_FtpUploadAttemptThenDefaultBasicAdminRule();
        Assert.False((await equal.EvaluateAsync(At(Ftp()))).Matched);
        Assert.False((await equal.EvaluateAsync(At(Http()))).Matched);
    }
    [Fact] public async Task UnknownCredentialAndNonAdminPathFail()
    {
        foreach (var http in new[] { Http(basic: "YWRtaW46c3Ryb25nLXBhc3M="), Http(path: "/status") })
        {
            var rule = new R569_FtpUploadAttemptThenDefaultBasicAdminRule();
            Assert.False((await rule.EvaluateAsync(At(Ftp()))).Matched);
            Assert.False((await rule.EvaluateAsync(At(http, 1))).Matched);
        }
    }
    [Fact] public async Task FtpReadAndWrongPeerDoNotSeed()
    {
        var rule = new R569_FtpUploadAttemptThenDefaultBasicAdminRule();
        Assert.False((await rule.EvaluateAsync(At(Ftp(command: "RETR synthetic.bin\r\n")))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Http(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Ftp(publicPeer: "1.1.1.1"), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Http(), 3))).Matched);
    }
    [Fact] public async Task ExpiredWindowAndDuplicatePacketIdsFail()
    {
        var late = new R569_FtpUploadAttemptThenDefaultBasicAdminRule();
        Assert.False((await late.EvaluateAsync(At(Ftp()))).Matched);
        Assert.False((await late.EvaluateAsync(At(Http(), 121))).Matched);
        var dup = new R569_FtpUploadAttemptThenDefaultBasicAdminRule();
        var ftp = Ftp(); var http = Http(); http.Id = ftp.Id;
        Assert.False((await dup.EvaluateAsync(At(ftp))).Matched);
        Assert.False((await dup.EvaluateAsync(At(http, 1))).Matched);
    }
    [Fact] public async Task EventDoesNotExposeCredentialsOrInfo()
    {
        var rule = new R569_FtpUploadAttemptThenDefaultBasicAdminRule();
        var ftp = Ftp(); ftp.Info = "private-marker";
        Assert.False((await rule.EvaluateAsync(At(ftp))).Matched);
        var evt = Assert.Single((await rule.EvaluateAsync(At(Http(), 1))).Events);
        var json = JsonSerializer.Serialize(evt);
        Assert.DoesNotContain("private-marker", json);
        Assert.DoesNotContain(SyntheticBasic, json);
    }
    [Fact] public void RegistryHasSingleCandidateShadowRegistration()
    {
        var rule = Assert.IsType<R569_FtpUploadAttemptThenDefaultBasicAdminRule>(
            Assert.Single(RuleRegistry.CreateDefaultRules().Where(x => x.Descriptor.RuleId == "R569")));
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
    }
}
