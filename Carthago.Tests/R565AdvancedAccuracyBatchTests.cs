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

public sealed class R565AdvancedAccuracyBatchTests
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

    [Fact]
    public void ActualPacketHandlerClassifiesRedactedHttpAndFtpCommandShapes()
    {
        var http = Http();
        Assert.True(http.HttpBasicDefaultCredentialObserved);
        Assert.Equal("HTTP", http.ApplicationProtocol);
        Assert.Contains("Authorization: [REDACTED]", http.HttpRequestHeaders);
        Assert.DoesNotContain(SyntheticBasic, http.HttpRequestHeaders);
        Assert.Equal("ftp.stor", Ftp().ApplicationProtocol);
        Assert.Equal("ftp.appe", Ftp(command: "APPE synthetic.bin\r\n").ApplicationProtocol);
        Assert.NotEqual("ftp.stor", Ftp(command: "RETR synthetic.bin\r\n").ApplicationProtocol);
    }

    [Fact]
    public async Task ReverseEndpointPairWithinTwoMinutesProducesOneHighCandidate()
    {
        var rule = new R565_DefaultBasicAdminThenFtpCallbackRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        var result = await rule.EvaluateAsync(At(Ftp(), 20));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R565", evt.RuleId);
        Assert.Equal(SeverityLevel.High, evt.Severity);
        Assert.Equal(1, evt.Count);
        Assert.Equal(120, evt.WindowSeconds);
    }

    [Fact]
    public async Task BenignNonDefaultCredentialAndDuplicateAuthorizationDoNotSeed()
    {
        var rule = new R565_DefaultBasicAdminThenFtpCallbackRule();
        var unknown = Http(basic: "YWRtaW46c3Ryb25nLXBhc3M=");
        var duplicate = Http(extra: "Authorization: Bearer synthetic\r\n");
        Assert.False(unknown.HttpBasicDefaultCredentialObserved);
        Assert.False(duplicate.HttpBasicDefaultCredentialObserved);
        Assert.False((await rule.EvaluateAsync(At(unknown))).Matched);
        Assert.False((await rule.EvaluateAsync(At(duplicate, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Ftp(), 2))).Matched);
    }

    [Fact]
    public async Task NonAdminRequestAndFtpReadNeverComplete()
    {
        var rule = new R565_DefaultBasicAdminThenFtpCallbackRule();
        Assert.False((await rule.EvaluateAsync(At(Http(path: "/status")))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Ftp(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Http(), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Ftp(command: "RETR synthetic.bin\r\n"), 3))).Matched);
    }

    [Fact]
    public async Task CallbackMustReachExactPublicOriginFromExactPrivateHost()
    {
        var rule = new R565_DefaultBasicAdminThenFtpCallbackRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Ftp(publicPeer: "9.9.9.9"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Ftp(internalHost: "10.42.1.21"), 2))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Ftp(), 3))).Matched);
    }

    [Theory]
    [InlineData("192.0.2.9")]
    [InlineData("198.51.100.9")]
    [InlineData("203.0.113.9")]
    [InlineData("100.64.1.9")]
    [InlineData("10.2.1.9")]
    public async Task ReservedOrPrivateRemotePeerDoesNotQualify(string peer)
    {
        var rule = new R565_DefaultBasicAdminThenFtpCallbackRule();
        Assert.False((await rule.EvaluateAsync(At(Http(publicPeer: peer)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Ftp(publicPeer: peer), 1))).Matched);
    }

    [Fact]
    public async Task ReverseOrderAndEqualTimestampDoNotQualify()
    {
        var reverse = new R565_DefaultBasicAdminThenFtpCallbackRule();
        Assert.False((await reverse.EvaluateAsync(At(Ftp()))).Matched);
        Assert.False((await reverse.EvaluateAsync(At(Http(), 1))).Matched);
        var equal = new R565_DefaultBasicAdminThenFtpCallbackRule();
        Assert.False((await equal.EvaluateAsync(At(Http()))).Matched);
        Assert.False((await equal.EvaluateAsync(At(Ftp()))).Matched);
    }

    [Fact]
    public async Task ExpiredWindowAndOutOfOrderObservationFailClosed()
    {
        var expired = new R565_DefaultBasicAdminThenFtpCallbackRule();
        Assert.False((await expired.EvaluateAsync(At(Http()))).Matched);
        Assert.False((await expired.EvaluateAsync(At(Ftp(), 121))).Matched);
        var order = new R565_DefaultBasicAdminThenFtpCallbackRule();
        Assert.False((await order.EvaluateAsync(At(Http(), 20))).Matched);
        Assert.False((await order.EvaluateAsync(At(Ftp(), 10))).Matched);
    }

    [Fact]
    public async Task DuplicatePacketIdCannotCompletePair()
    {
        var rule = new R565_DefaultBasicAdminThenFtpCallbackRule();
        var first = Http();
        var second = Ftp(); second.Id = first.Id;
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        Assert.False((await rule.EvaluateAsync(At(second, 1))).Matched);
    }

    [Fact]
    public async Task PortOnlyAndInfoOnlyFtpCannotCompletePair()
    {
        var rule = new R565_DefaultBasicAdminThenFtpCallbackRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        var fake = Ftp(); fake.ApplicationProtocol = null; fake.Info = "STOR secret.txt";
        Assert.False((await rule.EvaluateAsync(At(fake, 1))).Matched);
    }

    [Fact]
    public async Task ContradictoryTlsDnsQuicAndHttpMetadataFailClosed()
    {
        var rule = new R565_DefaultBasicAdminThenFtpCallbackRule();
        var tlsHttp = Http(); tlsHttp.TlsVersion = "TLS1.3";
        var dnsHttp = Http(); dnsHttp.DnsQname = "synthetic.test";
        var quicHttp = Http(); quicHttp.IsQuic = true;
        var httpFtp = Ftp(); httpFtp.HttpUri = "/admin";
        Assert.False((await rule.EvaluateAsync(At(tlsHttp))).Matched);
        Assert.False((await rule.EvaluateAsync(At(dnsHttp, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(quicHttp, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(httpFtp, 3))).Matched);
    }

    [Fact]
    public async Task ImportedRecordCannotForgeInternalHttpCredentialFlag()
    {
        var imported = JsonSerializer.Deserialize<TrafficRecord>(
            "{\"HttpBasicDefaultCredentialObserved\":true,\"Source\":\"8.8.8.8\",\"Destination\":\"10.42.1.20\",\"ApplicationProtocol\":\"HTTP\"}");
        Assert.NotNull(imported);
        Assert.False(imported.HttpBasicDefaultCredentialObserved);
        var rule = new R565_DefaultBasicAdminThenFtpCallbackRule();
        Assert.False((await rule.EvaluateAsync(At(imported))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Ftp(), 1))).Matched);
    }

    [Fact]
    public async Task SubsequentFtpRequiresFreshHttpAndCooldownSuppressesRepeatedChain()
    {
        var rule = new R565_DefaultBasicAdminThenFtpCallbackRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Ftp(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Ftp(), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Http(), 3))).Matched);
        var repeated = await rule.EvaluateAsync(At(Ftp(), 4));
        Assert.True(repeated.Suppressed);
        Assert.Empty(repeated.Events);
    }

    [Fact]
    public async Task ConcurrentDuplicateFtpPacketProducesAtMostOneMatch()
    {
        var rule = new R565_DefaultBasicAdminThenFtpCallbackRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        var same = Ftp();
        var results = await Task.WhenAll(
            rule.EvaluateAsync(At(same, 1)).AsTask(),
            rule.EvaluateAsync(At(same, 1)).AsTask());
        Assert.Equal(1, results.Count(x => x.Matched));
    }

    [Fact]
    public async Task DetectionEventRedactsCredentialsPathsAndRawInfo()
    {
        var rule = new R565_DefaultBasicAdminThenFtpCallbackRule();
        var http = Http();
        http.Info = "private-http-marker";
        var ftp = Ftp(command: "STOR unique-secret-filename.bin\r\n");
        ftp.Info = "private-ftp-marker";
        Assert.False((await rule.EvaluateAsync(At(http))).Matched);
        var result = await rule.EvaluateAsync(At(ftp, 1));
        var serialized = JsonSerializer.Serialize(Assert.Single(result.Events));
        Assert.DoesNotContain(SyntheticBasic, serialized);
        Assert.DoesNotContain("unique-secret-filename", serialized);
        Assert.DoesNotContain("private-http-marker", serialized);
        Assert.DoesNotContain("private-ftp-marker", serialized);
        Assert.DoesNotContain("gateway.lab.internal", serialized);
        Assert.Contains("ftp.transfer_status", serialized);
    }

    [Fact]
    public void RuleIsRegisteredOnceWithCandidateShadowAndConfidenceFloor()
    {
        var rules = RuleRegistry.CreateDefaultRules()
            .Where(r => r.Descriptor.RuleId == "R565").ToArray();
        var rule = Assert.IsType<R565_DefaultBasicAdminThenFtpCallbackRule>(Assert.Single(rules));
        Assert.Equal("Rules.R565.Enabled", rule.Descriptor.ConfigKey);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(90, rule.PrecisionProfile.MinimumConfidence);
    }
}
