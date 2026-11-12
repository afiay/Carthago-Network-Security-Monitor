// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Tests authored before detector source; not executed.
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
public sealed class R896R900ObservableCandidateBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 12, 0, 0, 0, DateTimeKind.Utc);
    public static TheoryData<string> Cases => new() { "R896", "R897", "R898", "R899", "R900" };
    private static readonly string[] Ids = { "R896", "R897", "R898", "R899", "R900" };
    private static IDetectionRule Rule(string id) => id switch
    {
        "R896" => new R896_Regsvr32PublicScriptletHttpGetRule(),
        "R897" => new R897_CmstpPublicInfHttpGetRule(),
        "R898" => new R898_NetPrivateSmbSynPeerFanoutRule(),
        "R899" => new R899_VmwarePublicResolverTlsSniRule(),
        "R900" => new R900_RegasmPublicSynThenTlsRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };
    private static int Count(string id) => id == "R898" ? 3 : id == "R900" ? 2 : 1;
    private static TrafficRecord Packet(string id, int stage)
    {
        var r = new TrafficRecord { Id = Guid.NewGuid(), IpVersion = 4, Source = "10.1.1.10",
            Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 443, IsTcp = true,
            Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0, ProcessId = 310,
            Info = "SECRET-RAW-INFO-MARKER" };
        switch (id)
        {
            case "R896": r.ProcessName = "regsvr32.exe"; Http(r, "/payload.sct"); break;
            case "R897": r.ProcessName = "cmstp.exe"; Http(r, "/profile.inf"); break;
            case "R898": r.ProcessName = "net.exe"; r.DestinationPort = 445;
                r.Destination = "10.1.2." + (20 + stage); break;
            case "R899": r.ProcessName = "hostd"; Tls(r, "dns.google"); break;
            case "R900": r.ProcessName = "regasm.exe"; if (stage == 1) Tls(r, "service.example.net"); break;
        }
        return r;
    }
    private static void Data(TrafficRecord r) { r.TcpFlags = 0x18; r.L4Len = 520; r.Length = 560; }
    private static void Http(TrafficRecord r, string uri)
    { Data(r); r.DestinationPort = 80; r.ApplicationProtocol = "HTTP"; r.HttpMethod = "GET";
      r.HttpUri = uri; r.HttpHost = "service.example.net"; }
    private static void Tls(TrafficRecord r, string sni)
    { Data(r); r.TlsVersion = "TLS1.3"; r.Sni = sni; }
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
    public async Task WrongProcessMissingAndContradictoryEvidence(string id)
    {
        var wrong = Rule(id); var missing = Rule(id); var conflict = Rule(id);
        for (var i = 0; i < Count(id); i++)
        {
            var a = Packet(id, i); a.ProcessName = "explorer.exe";
            Assert.False((await wrong.EvaluateAsync(At(a, i * 3))).Matched);
            var b = Packet(id, i); b.ProcessId = 0;
            Assert.False((await missing.EvaluateAsync(At(b, i * 3))).Matched);
            var c = Packet(id, i); c.IsTcp = c.IsUdp = true;
            Assert.False((await conflict.EvaluateAsync(At(c, i * 3))).Matched);
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
                case "R896": r.HttpUri = "/payload.sct.txt"; break;
                case "R897": r.HttpUri = "/profile.inf.bak"; break;
                case "R898": r.DestinationPort = 139; break;
                case "R899": r.Sni = "dns.google.example.net"; break;
                case "R900": r.DestinationPort = 8443; break;
            }
            Assert.False((await rule.EvaluateAsync(At(r, i * 3))).Matched);
        }
    }
    [Theory, MemberData(nameof(Cases))]
    public async Task CooldownAndRecovery(string id)
    {
        var rule = Rule(id);
        Assert.True((await Trigger(rule, id, 0)).Matched);
        Assert.True((await Trigger(rule, id, 300)).Suppressed);
        Assert.True((await Trigger(rule, id, 950)).Matched);
    }
    [Theory, MemberData(nameof(Cases))]
    public async Task DuplicateAndReverseTimeFailClosed(string id)
    {
        var rule = Rule(id); var first = Packet(id, 0);
        await rule.EvaluateAsync(At(first, 100));
        if (Count(id) == 1)
        {
            Assert.False((await rule.EvaluateAsync(At(first, 101))).Matched);
            Assert.False((await rule.EvaluateAsync(At(Packet(id, 0), 99))).Matched);
        }
        else
        {
            for (var i = 1; i < Count(id); i++)
            {
                var copy = Packet(id, i); copy.Id = first.Id;
                Assert.False((await rule.EvaluateAsync(At(copy, 100 + i))).Matched);
            }
            var reverse = Rule(id);
            await reverse.EvaluateAsync(At(Packet(id, 0), 100));
            for (var i = 1; i < Count(id); i++)
                Assert.False((await reverse.EvaluateAsync(At(Packet(id, i), 100 - i))).Matched);
        }
    }
    [Fact]
    public async Task FanoutRequiresDistinctPeersSamePidAndBoundedWindow()
    {
        foreach (var variant in new[] { "peer", "pid", "expiry" })
        {
            var rule = Rule("R898");
            for (var i = 0; i < 3; i++)
            {
                var r = Packet("R898", i);
                if (variant == "peer") r.Destination = "10.1.2.20";
                if (variant == "pid") r.ProcessId += i;
                Assert.False((await rule.EvaluateAsync(At(r, variant == "expiry" ? i * 60 : i * 3))).Matched);
            }
        }
    }
    [Fact]
    public async Task RegistrationTlsRequiresSameFlowAndWindow()
    {
        foreach (var variant in new[] { "port", "peer", "pid", "expiry", "no-tls" })
        {
            var rule = Rule("R900");
            await rule.EvaluateAsync(At(Packet("R900", 0), 0));
            var r = Packet("R900", 1);
            if (variant == "port") r.SourcePort = 51001;
            if (variant == "peer") r.Destination = "9.9.9.9";
            if (variant == "pid") r.ProcessId++;
            if (variant == "no-tls") r.TlsVersion = null;
            Assert.False((await rule.EvaluateAsync(At(r, variant == "expiry" ? 60 : 3))).Matched);
        }
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
