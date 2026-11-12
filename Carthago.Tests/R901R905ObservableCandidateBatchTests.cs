// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Test source authored first; no builds/tests executed.
using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R901R905ObservableCandidateBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 12, 0, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids = { "R901", "R902", "R903", "R904", "R905" };
    public static TheoryData<string> Cases => new() { "R901", "R902", "R903", "R904", "R905" };
    private static IDetectionRule Rule(string id) => id switch
    {
        "R901" => new R901_NltestLdapThenGlobalCatalogSynRule(),
        "R902" => new R902_PublicSshThenScreensharingVncResponseRule(),
        "R903" => new R903_PowershellSmbWriteThenWinRmSynRule(),
        "R904" => new R904_CurlPublicBinaryHttpPutRule(),
        "R905" => new R905_MmcPrivateSmbThenPublicTlsRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };
    private static int Count(string id) => id == "R904" ? 1 : 2;
    private static TrafficRecord Packet(string id, int stage)
    {
        var r = new TrafficRecord { Id = Guid.NewGuid(), IpVersion = 4, Source = "10.1.1.10",
            Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 443,
            IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, L4Len = 0, Length = 40,
            ProcessId = 310, Info = "SECRET-RAW-INFO-MARKER" };
        switch (id)
        {
            case "R901":
                r.ProcessName = "nltest.exe"; r.DestinationPort = stage == 0 ? 389 : 3268; break;
            case "R902":
                if (stage == 0) { r.Source = "8.8.8.8"; r.DestinationPort = 22; r.ProcessId = 0; }
                else { r.Source = "10.1.2.45"; r.Destination = "8.8.8.8";
                    r.SourcePort = 5900; r.DestinationPort = 52000; r.TcpFlags = 0x12;
                    r.ProcessName = "screensharingd"; }
                break;
            case "R903":
                r.ProcessName = "powershell.exe"; r.DestinationPort = stage == 0 ? 445 : 5985;
                if (stage == 0) { Data(r, 620); r.ApplicationProtocol = "smb2.write.request"; }
                break;
            case "R904":
                r.ProcessName = "curl.exe"; r.Destination = "8.8.8.8"; r.DestinationPort = 80;
                Data(r, 900); r.ApplicationProtocol = "HTTP"; r.HttpMethod = "PUT";
                r.HttpUri = "/upload/artifact"; r.HttpHost = "service.example.net";
                r.HttpRequestHeaders = "Host: service.example.net\r\nContent-Type: application/octet-stream\r\n";
                break;
            case "R905":
                r.ProcessName = "mmc.exe"; r.DestinationPort = 445;
                if (stage == 1) { r.Destination = "8.8.8.8"; r.DestinationPort = 443;
                    Data(r, 650); r.TlsVersion = "TLS1.3"; r.Sni = "service.example.net"; }
                break;
        }
        return r;
    }
    private static void Data(TrafficRecord r, int size)
    { r.TcpFlags = 0x18; r.L4Len = size; r.Length = size + 40; }
    private static RuleEvaluationContext At(TrafficRecord r, double seconds)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));
    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, int start)
    {
        RuleEvaluationResult? result = null;
        for (var i = 0; i < Count(id); i++)
        {
            result = await rule.EvaluateAsync(At(Packet(id, i), start + i * 3));
            if (i < Count(id) - 1) Assert.False(result.Matched);
        }
        return result!;
    }

    [Theory, MemberData(nameof(Cases))]
    public async Task PositiveAndPrivacy(string id)
    {
        var result = await Trigger(Rule(id), id, 0);
        Assert.True(result.Matched);
        Assert.DoesNotContain("SECRET-RAW-INFO-MARKER", JsonSerializer.Serialize(result.Events));
    }
    [Theory, MemberData(nameof(Cases))]
    public async Task MissingAndContradictoryEvidence(string id)
    {
        var noProcess = Rule(id); var conflict = Rule(id); var missing = Rule(id);
        for (var i = 0; i < Count(id); i++)
        {
            var a = Packet(id, i); a.ProcessId = 0;
            Assert.False((await noProcess.EvaluateAsync(At(a, i * 3))).Matched);
            var b = Packet(id, i); b.IsTcp = b.IsUdp = true;
            Assert.False((await conflict.EvaluateAsync(At(b, i * 3))).Matched);
            var c = Packet(id, i); c.Destination = null;
            Assert.False((await missing.EvaluateAsync(At(c, i * 3))).Matched);
        }
    }
    [Theory, MemberData(nameof(Cases))]
    public async Task BenignNearMiss(string id)
    {
        var rule = Rule(id);
        for (var i = 0; i < Count(id); i++)
        {
            var r = Packet(id, i);
            switch (id)
            {
                case "R901": r.DestinationPort = 636; break;
                case "R902": r.ProcessName = "other"; break;
                case "R903": r.DestinationPort = 5986; break;
                case "R904": r.HttpMethod = "GET"; break;
                case "R905": r.ProcessName = "explorer.exe"; break;
            }
            Assert.False((await rule.EvaluateAsync(At(r, i * 3))).Matched);
        }
    }
    [Theory, MemberData(nameof(Cases))]
    public async Task CooldownRecovery(string id)
    {
        var rule = Rule(id);
        Assert.True((await Trigger(rule, id, 0)).Matched);
        Assert.True((await Trigger(rule, id, 300)).Suppressed);
        Assert.True((await Trigger(rule, id, 950)).Matched);
    }
    [Theory, MemberData(nameof(Cases))]
    public async Task DuplicateReverseAndExpiry(string id)
    {
        var first = Packet(id, 0); var dup = Rule(id);
        await dup.EvaluateAsync(At(first, 100));
        if (Count(id) == 1)
        {
            Assert.False((await dup.EvaluateAsync(At(first, 101))).Matched);
            Assert.False((await dup.EvaluateAsync(At(Packet(id, 0), 99))).Matched);
            return;
        }
        var second = Packet(id, 1); second.Id = first.Id;
        Assert.False((await dup.EvaluateAsync(At(second, 103))).Matched);
        var reverse = Rule(id);
        await reverse.EvaluateAsync(At(Packet(id, 0), 100));
        Assert.False((await reverse.EvaluateAsync(At(Packet(id, 1), 99))).Matched);
        var expired = Rule(id);
        await expired.EvaluateAsync(At(Packet(id, 0), 0));
        Assert.False((await expired.EvaluateAsync(At(Packet(id, 1), 46))).Matched);
    }
    [Theory]
    [InlineData("R901")]
    [InlineData("R902")]
    [InlineData("R903")]
    [InlineData("R905")]
    public async Task CorrelationRejectsUnrelatedEndpoint(string id)
    {
        var rule = Rule(id);
        await rule.EvaluateAsync(At(Packet(id, 0), 0));
        var second = Packet(id, 1);
        if (id == "R905") second.Source = "10.1.1.11";
        else second.Destination = id == "R902" ? "9.9.9.9" : "10.1.2.46";
        Assert.False((await rule.EvaluateAsync(At(second, 3))).Matched);
    }
    [Theory]
    [InlineData("R901")]
    [InlineData("R903")]
    [InlineData("R905")]
    public async Task CorrelationRejectsDifferentPid(string id)
    {
        var rule = Rule(id);
        await rule.EvaluateAsync(At(Packet(id, 0), 0));
        var second = Packet(id, 1); second.ProcessId++;
        Assert.False((await rule.EvaluateAsync(At(second, 3))).Matched);
    }
    [Fact]
    public async Task BinaryContentTypeMustBeExactSingleHeader()
    {
        foreach (var headers in new[] { "X-Content-Type: application/octet-stream",
            "Content-Type: text/plain", "Content-Type: application/octet-stream\r\nContent-Type: text/plain",
            "Content-Type: application/octet-stream-malicious" })
        {
            var r = Packet("R904", 0); r.HttpRequestHeaders = headers;
            Assert.False((await Rule("R904").EvaluateAsync(At(r, 0))).Matched);
        }
    }
    [Fact]
    public async Task SmbWriteRequiresTypedRequestNotInfo()
    {
        var rule = Rule("R903");
        var first = Packet("R903", 0); first.ApplicationProtocol = null; first.Info = "smb2.write.request";
        await rule.EvaluateAsync(At(first, 0));
        Assert.False((await rule.EvaluateAsync(At(Packet("R903", 1), 3))).Matched);
    }
    [Fact]
    public async Task BatchPredicatesStayIndependent()
    {
        foreach (var id in Ids)
            foreach (var other in Ids.Where(x => x != id))
            {
                var rule = Rule(id);
                for (var i = 0; i < Count(other); i++)
                    Assert.False((await rule.EvaluateAsync(At(Packet(other, i), i * 3))).Matched);
            }
    }
    [Fact]
    public void RegistryUniqueCandidateShadow()
    {
        var rules = RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count, rules.Select(r => r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var id in Ids)
        {
            var rule = Assert.Single(rules.Where(r => r.Descriptor.RuleId == id));
            var profile = Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(rule).PrecisionProfile;
            Assert.Equal(RulePrecisionMaturity.Candidate, profile.Maturity);
            Assert.Equal(RuleRuntimeMode.Shadow, profile.DefaultMode);
        }
    }
}
