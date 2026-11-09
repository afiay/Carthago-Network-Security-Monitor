// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit source authored, 0 tests executed.
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

public sealed class R776R785AdvancedAccuracyBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 9, 0, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids = { "R776", "R777", "R778", "R779", "R780", "R781", "R782", "R783", "R784", "R785" };
    private static IDetectionRule Rule(string id) => id switch
    {
        "R776" => new R776_WindowsPowerShellPasteHttpPostBurstRule(),
        "R777" => new R777_WindowsGitRepositoryHttpPostBurstRule(),
        "R778" => new R778_WindowsExcelCloudStorageTlsBurstRule(),
        "R779" => new R779_Windows7ZipUncommonPortTlsBurstRule(),
        "R780" => new R780_WindowsPowerShellFtpPortPayloadBurstRule(),
        "R781" => new R781_EsxiHostdTextStorageTlsBurstRule(),
        "R782" => new R782_LinuxTarCloudStorageTlsBurstRule(),
        "R783" => new R783_LinuxRsyncFtpPortPayloadBurstRule(),
        "R784" => new R784_MacOsascriptTextStorageHttpPostBurstRule(),
        "R785" => new R785_MacLaunchdFixedSizeTlsCadenceRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };
    private static (string Process, string Kind, int Port, string Host, int Threshold, int Seconds) Spec(string id) => id switch
    {
        "R776" => ("powershell.exe", "http", 80, "pastebin.com", 5, 20),
        "R777" => ("git.exe", "http", 80, "github.com", 5, 20),
        "R778" => ("excel.exe", "tls", 443, "drive.google.com", 5, 30),
        "R779" => ("7z.exe", "tls", 8443, "updates.example.net", 5, 30),
        "R780" => ("powershell.exe", "tcp", 21, "", 6, 20),
        "R781" => ("hostd", "tls", 443, "pastebin.com", 5, 30),
        "R782" => ("tar", "tls", 443, "drive.google.com", 5, 30),
        "R783" => ("rsync", "tcp", 21, "", 6, 20),
        "R784" => ("osascript", "http", 80, "paste.ee", 5, 20),
        "R785" => ("launchd", "cadence", 443, "api.example.net", 4, 100),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };
    private static TrafficRecord Packet(string id, int length = 240)
    {
        var s = Spec(id);
        var r = new TrafficRecord
        {
            Id = Guid.NewGuid(), Source = "10.70.80.20", Destination = "8.8.4.4",
            IpVersion = 4, Protocol = "TCP", IsTcp = true, IsUdp = false,
            IsQuic = false, SourcePort = 51000, DestinationPort = s.Port,
            TcpFlags = 0x18, L4Len = length, Length = length + 40,
            ProcessName = s.Process, ProcessId = 8100,
            Info = "RAW-SECRET-MARKER"
        };
        if (s.Kind == "http")
        {
            r.ApplicationProtocol = "HTTP";
            r.HttpMethod = "POST";
            r.HttpUri = "/api/upload?token=PRIVATE-SECRET";
            r.HttpHost = s.Host;
            r.HttpRequestHeaders = "Host: " + s.Host + "\r\n\r\n";
        }
        else if (s.Kind == "tls" || s.Kind == "cadence")
        {
            r.TlsVersion = "TLS1.2";
            r.Sni = s.Host;
        }
        return r;
    }
    private static RuleEvaluationContext At(TrafficRecord r, double seconds)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, double start)
    {
        var s = Spec(id);
        RuleEvaluationResult? last = null;
        for (var i = 0; i < s.Threshold; i++)
            last = await rule.EvaluateAsync(At(Packet(id), start + i * (s.Kind == "cadence" ? 20 : 2)));
        return last!;
    }

    [Theory]
    [InlineData("R776")]
    [InlineData("R777")]
    [InlineData("R778")]
    [InlineData("R779")]
    [InlineData("R780")]
    [InlineData("R781")]
    [InlineData("R782")]
    [InlineData("R783")]
    [InlineData("R784")]
    [InlineData("R785")]
    public async Task PositiveAndBenignNearMissAndMissingProcess(string id)
    {
        var s = Spec(id);
        var near = Rule(id);
        for (var i = 0; i < s.Threshold + 2; i++)
        {
            var packet = Packet(id);
            packet.ProcessName = "unrelated.exe";
            Assert.False((await near.EvaluateAsync(At(packet, i * 2))).Matched);
        }
        var missing = Packet(id);
        missing.ProcessId = 0;
        Assert.False((await near.EvaluateAsync(At(missing, 40))).Matched);
        var actual = Rule(id);
        Assert.True((await Trigger(actual, id, 0)).Matched);
    }

    [Theory]
    [InlineData("R776")]
    [InlineData("R777")]
    [InlineData("R778")]
    [InlineData("R779")]
    [InlineData("R780")]
    [InlineData("R781")]
    [InlineData("R782")]
    [InlineData("R783")]
    [InlineData("R784")]
    [InlineData("R785")]
    public async Task ContradictoryTransportAndReverseTimeAndDuplicateIdsFailClosed(string id)
    {
        var s = Spec(id);
        var bad = Rule(id);
        for (var i = 0; i < s.Threshold; i++)
        {
            var r = Packet(id); r.IsUdp = true;
            Assert.False((await bad.EvaluateAsync(At(r, i * 2))).Matched);
        }
        var replay = Rule(id);
        var first = Packet(id);
        await replay.EvaluateAsync(At(first, 0));
        for (var i = 1; i < s.Threshold; i++)
        {
            var duplicate = Packet(id); duplicate.Id = first.Id;
            Assert.False((await replay.EvaluateAsync(At(duplicate, i * 2))).Matched);
        }
        var reverse = Packet(id);
        Assert.False((await replay.EvaluateAsync(At(reverse, -1))).Matched);
        var expiry = Rule(id);
        await expiry.EvaluateAsync(At(Packet(id), 0));
        for (var i = 1; i < s.Threshold; i++)
            Assert.False((await expiry.EvaluateAsync(At(Packet(id), s.Seconds + i * 2))).Matched);
    }

    [Theory]
    [InlineData("R776")]
    [InlineData("R777")]
    [InlineData("R778")]
    [InlineData("R779")]
    [InlineData("R780")]
    [InlineData("R781")]
    [InlineData("R782")]
    [InlineData("R783")]
    [InlineData("R784")]
    [InlineData("R785")]
    public async Task CooldownRecoveryAndEvidencePrivacy(string id)
    {
        var rule = Rule(id);
        var first = await Trigger(rule, id, 0);
        Assert.True(first.Matched);
        var serialized = JsonSerializer.Serialize(first.Events);
        Assert.DoesNotContain("RAW-SECRET-MARKER", serialized);
        Assert.DoesNotContain("PRIVATE-SECRET", serialized);
        var suppressed = await Trigger(rule, id, 150);
        Assert.True(suppressed.Suppressed);
        Assert.Empty(suppressed.Events);
        Assert.True((await Trigger(rule, id, 850)).Matched);
    }

    [Fact]
    public async Task NeighboringPredicatesAreNotConverged()
    {
        for (var i = 0; i < Ids.Length; i++)
        {
            var id = Ids[i];
            var other = Ids[(i + 1) % Ids.Length];
            var rule = Rule(id);
            var threshold = Spec(id).Threshold;
            for (var j = 0; j < threshold + 2; j++)
                Assert.False((await rule.EvaluateAsync(At(Packet(other), j * 2))).Matched);
        }
    }

    [Fact]
    public void RegistryContainsExactlyTenNewCandidateShadowRulesAndUniqueIds()
    {
        var rules = RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count, rules.Select(r => r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var id in Ids)
        {
            var found = Assert.Single(rules.Where(r => r.Descriptor.RuleId == id));
            var precision = Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(found);
            Assert.Equal(RulePrecisionMaturity.Candidate, precision.PrecisionProfile.Maturity);
            Assert.Equal(RuleRuntimeMode.Shadow, precision.PrecisionProfile.DefaultMode);
        }
    }
}
