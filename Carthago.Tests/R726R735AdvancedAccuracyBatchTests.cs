// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed.
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

public sealed class R726R735AdvancedAccuracyBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 4, 14, 0, 0, DateTimeKind.Utc);

    private static IDetectionRule Rule(string id) => id switch
    {
        "R726" => new R726_EsxiManagementProcessExternalTlsBurstRule(),
        "R727" => new R727_LinuxScriptProcessDirectExternalDotRule(),
        "R728" => new R728_NodeRuntimePrivateOtServiceSynRule(),
        "R729" => new R729_PythonRuntimePrivateOtServiceSynRule(),
        "R730" => new R730_UnixShellPrivateOtServiceSynRule(),
        "R731" => new R731_WindowsNetworkToolOutboundFloodShapeRule(),
        "R732" => new R732_LinuxNetworkToolOutboundFloodShapeRule(),
        "R733" => new R733_MacProcessTextStorageTlsContactRule(),
        "R734" => new R734_MacNonBrowserExternalTlsPayloadBurstRule(),
        "R735" => new R735_EsxiProcessWebProtocolPortMismatchRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static RuleEvaluationContext At(TrafficRecord r, double seconds)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    private static TrafficRecord Tls(
        string process,
        string sni,
        int port = 443,
        int l4 = 1600,
        int pid = 5100)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "10.20.30.40",
            Destination = "8.8.8.8",
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            IsUdp = false,
            IsQuic = false,
            SourcePort = 52000,
            DestinationPort = port,
            TcpFlags = 0x18,
            L4Len = l4,
            Length = l4 + 40,
            TlsVersion = "TLS1.3",
            Sni = sni,
            ProcessName = process,
            ProcessId = pid,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord Syn(
        string process,
        string destination,
        int port,
        int pid = 5200)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "10.20.30.40",
            Destination = destination,
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            IsUdp = false,
            IsQuic = false,
            SourcePort = 53000,
            DestinationPort = port,
            TcpFlags = 0x02,
            L4Len = null,
            Length = 40,
            ProcessName = process,
            ProcessId = pid,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord FloodTcp(string process, int pid = 5300)
        => Syn(process, "8.8.4.4", 4444, pid);

    private static TrafficRecord FloodUdp(string process, int pid = 5301)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "10.20.30.40",
            Destination = "8.8.4.4",
            IpVersion = 4,
            Protocol = "UDP",
            IsTcp = false,
            IsUdp = true,
            IsQuic = false,
            SourcePort = 54000,
            DestinationPort = 4444,
            L4Len = 96,
            Length = 124,
            ProcessName = process,
            ProcessId = pid,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord HttpMismatch(string process, int pid = 5400)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "10.20.30.40",
            Destination = "8.8.8.8",
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            IsUdp = false,
            IsQuic = false,
            SourcePort = 55000,
            DestinationPort = 902,
            TcpFlags = 0x18,
            L4Len = 220,
            Length = 260,
            ApplicationProtocol = "HTTP",
            HttpMethod = "GET",
            HttpUri = "/sdk?token=VERY-PRIVATE",
            HttpHost = "esxi.example",
            HttpRequestHeaders = "Host: esxi.example\r\n",
            ProcessName = process,
            ProcessId = pid,
            Info = "RAW-SECRET-MARKER"
        };

    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, int start)
    {
        switch (id)
        {
            case "R726":
                for (var i = 0; i < 3; i++)
                    await rule.EvaluateAsync(At(Tls("hostd", "updates.vendor.example", l4: 1600), start + i));
                return await rule.EvaluateAsync(At(Tls("hostd", "updates.vendor.example", l4: 1600), start + 3));

            case "R727":
                return await rule.EvaluateAsync(At(Tls("python3", "dns.example", port: 853, l4: 180), start));

            case "R728":
                return await rule.EvaluateAsync(At(Syn("node", "10.20.31.50", 502), start));

            case "R729":
                return await rule.EvaluateAsync(At(Syn("python3", "10.20.31.50", 44818), start));

            case "R730":
                return await rule.EvaluateAsync(At(Syn("bash", "10.20.31.50", 102), start));

            case "R731":
                for (var i = 0; i < 11; i++)
                    await rule.EvaluateAsync(At(FloodTcp("powershell.exe"), start + i * 0.8));
                return await rule.EvaluateAsync(At(FloodTcp("powershell.exe"), start + 8.8));

            case "R732":
                for (var i = 0; i < 11; i++)
                    await rule.EvaluateAsync(At(FloodUdp("python3"), start + i * 0.8));
                return await rule.EvaluateAsync(At(FloodUdp("python3"), start + 8.8));

            case "R733":
                return await rule.EvaluateAsync(At(Tls("osascript", "pastebin.com", l4: 220), start));

            case "R734":
                for (var i = 0; i < 3; i++)
                    await rule.EvaluateAsync(At(Tls("python3", "api.vendor.example", l4: 1600), start + i));
                return await rule.EvaluateAsync(At(Tls("python3", "api.vendor.example", l4: 1600), start + 3));

            case "R735":
                return await rule.EvaluateAsync(At(HttpMismatch("hostd"), start));

            default:
                throw new ArgumentOutOfRangeException(nameof(id));
        }
    }

    private static async Task<RuleEvaluationResult> NearMiss(IDetectionRule rule, string id)
    {
        switch (id)
        {
            case "R726":
                for (var i = 0; i < 3; i++)
                    await rule.EvaluateAsync(At(Tls("chrome.exe", "updates.vendor.example"), i));
                return await rule.EvaluateAsync(At(Tls("chrome.exe", "updates.vendor.example"), 3));

            case "R727":
                return await rule.EvaluateAsync(At(Tls("python3", "dns.example", port: 443), 0));

            case "R728":
                return await rule.EvaluateAsync(At(Syn("node", "8.8.8.8", 502), 0));

            case "R729":
                return await rule.EvaluateAsync(At(Syn("python3", "10.20.31.50", 443), 0));

            case "R730":
                return await rule.EvaluateAsync(At(Syn("systemd", "10.20.31.50", 102), 0));

            case "R731":
                for (var i = 0; i < 11; i++)
                    await rule.EvaluateAsync(At(FloodTcp("chrome.exe"), i % 9));
                return await rule.EvaluateAsync(At(FloodTcp("chrome.exe"), 9));

            case "R732":
                for (var i = 0; i < 11; i++)
                    await rule.EvaluateAsync(At(FloodUdp("systemd"), i % 9));
                return await rule.EvaluateAsync(At(FloodUdp("systemd"), 9));

            case "R733":
                return await rule.EvaluateAsync(At(Tls("safari", "pastebin.com", l4: 220), 0));

            case "R734":
                for (var i = 0; i < 3; i++)
                    await rule.EvaluateAsync(At(Tls("python3", "github.com"), i));
                return await rule.EvaluateAsync(At(Tls("python3", "github.com"), 3));

            case "R735":
                return await rule.EvaluateAsync(At(Tls("hostd", "esxi.example", port: 443), 0));

            default:
                throw new ArgumentOutOfRangeException(nameof(id));
        }
    }

    private static async Task<RuleEvaluationResult> MissingTelemetry(IDetectionRule rule, string id)
    {
        TrafficRecord r = id switch
        {
            "R726" => Tls("hostd", "updates.vendor.example"),
            "R727" => Tls("python3", "dns.example", port: 853, l4: 180),
            "R728" => Syn("node", "10.20.31.50", 502),
            "R729" => Syn("python3", "10.20.31.50", 44818),
            "R730" => Syn("bash", "10.20.31.50", 102),
            "R731" => FloodTcp("powershell.exe"),
            "R732" => FloodUdp("python3"),
            "R733" => Tls("osascript", "pastebin.com", l4: 220),
            "R734" => Tls("python3", "api.vendor.example"),
            "R735" => HttpMismatch("hostd"),
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };

        r.ProcessId = 0;
        return await rule.EvaluateAsync(At(r, 0));
    }

    private static async Task<RuleEvaluationResult> Contradictory(IDetectionRule rule, string id)
    {
        TrafficRecord r = id switch
        {
            "R726" => Tls("hostd", "updates.vendor.example"),
            "R727" => Tls("python3", "dns.example", port: 853, l4: 180),
            "R728" => Syn("node", "10.20.31.50", 502),
            "R729" => Syn("python3", "10.20.31.50", 44818),
            "R730" => Syn("bash", "10.20.31.50", 102),
            "R731" => FloodTcp("powershell.exe"),
            "R732" => FloodUdp("python3"),
            "R733" => Tls("osascript", "pastebin.com", l4: 220),
            "R734" => Tls("python3", "api.vendor.example"),
            "R735" => HttpMismatch("hostd"),
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };

        if (r.IsUdp) r.IsTcp = true;
        else r.IsUdp = true;
        return await rule.EvaluateAsync(At(r, 0));
    }

    [Theory]
    [InlineData("R726")][InlineData("R727")][InlineData("R728")][InlineData("R729")][InlineData("R730")]
    [InlineData("R731")][InlineData("R732")][InlineData("R733")][InlineData("R734")][InlineData("R735")]
    public async Task PositiveShapeMatchesAndEventDoesNotLeakRawInfo(string id)
    {
        var result = await Trigger(Rule(id), id, 0);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        var json = JsonSerializer.Serialize(evt);
        Assert.Contains("workbook.R", json);
        Assert.DoesNotContain("RAW-SECRET-MARKER", json);
        Assert.DoesNotContain("VERY-PRIVATE", json);
    }

    [Theory]
    [InlineData("R726")][InlineData("R727")][InlineData("R728")][InlineData("R729")][InlineData("R730")]
    [InlineData("R731")][InlineData("R732")][InlineData("R733")][InlineData("R734")][InlineData("R735")]
    public async Task BenignNearMissMissingTelemetryAndContradictoryTransportDoNotMatch(string id)
    {
        Assert.False((await NearMiss(Rule(id), id)).Matched);
        Assert.False((await MissingTelemetry(Rule(id), id)).Matched);
        Assert.False((await Contradictory(Rule(id), id)).Matched);
    }

    [Fact]
    public async Task StatefulBurstRulesRejectDuplicateReverseTimeAndExpiredWindow()
    {
        var esxi = Rule("R726");
        var first = Tls("hostd", "updates.vendor.example");
        await esxi.EvaluateAsync(At(first, 0));
        var dup = Tls("hostd", "updates.vendor.example"); dup.Id = first.Id;
        Assert.False((await esxi.EvaluateAsync(At(dup, 1))).Matched);
        Assert.False((await esxi.EvaluateAsync(At(Tls("hostd", "updates.vendor.example"), -1))).Matched);

        var expired = Rule("R726");
        await expired.EvaluateAsync(At(Tls("hostd", "updates.vendor.example"), 0));
        await expired.EvaluateAsync(At(Tls("hostd", "updates.vendor.example"), 1));
        await expired.EvaluateAsync(At(Tls("hostd", "updates.vendor.example"), 2));
        Assert.False((await expired.EvaluateAsync(At(Tls("hostd", "updates.vendor.example"), 121))).Matched);

        var flood = Rule("R731");
        var f = FloodTcp("powershell.exe");
        await flood.EvaluateAsync(At(f, 0));
        var same = FloodTcp("powershell.exe"); same.Id = f.Id;
        Assert.False((await flood.EvaluateAsync(At(same, 1))).Matched);

        for (var i = 0; i < 10; i++)
            await flood.EvaluateAsync(At(FloodTcp("powershell.exe"), 20 + i));
        Assert.False((await flood.EvaluateAsync(At(FloodTcp("powershell.exe"), 31))).Matched);

        var mac = Rule("R734");
        await mac.EvaluateAsync(At(Tls("python3", "api.vendor.example"), 10));
        Assert.False((await mac.EvaluateAsync(At(Tls("python3", "api.vendor.example"), 9))).Matched);
    }

    [Theory]
    [InlineData("R726")][InlineData("R727")][InlineData("R728")][InlineData("R729")][InlineData("R730")]
    [InlineData("R731")][InlineData("R732")][InlineData("R733")][InlineData("R734")][InlineData("R735")]
    public async Task EveryRuleHasIndependentCooldownAndRecovery(string id)
    {
        var rule = Rule(id);
        Assert.True((await Trigger(rule, id, 0)).Matched);

        var repeat = await Trigger(rule, id, 20);
        Assert.True(repeat.Suppressed);
        Assert.Empty(repeat.Events);

        Assert.True((await Trigger(rule, id, 620)).Matched);
    }

    [Fact]
    public async Task RuntimeAndPlatformPredicatesRemainIndependent()
    {
        Assert.False((await Rule("R728").EvaluateAsync(At(
            Syn("python3", "10.20.31.50", 502), 0))).Matched);
        Assert.False((await Rule("R729").EvaluateAsync(At(
            Syn("node", "10.20.31.50", 44818), 0))).Matched);
        Assert.False((await Rule("R730").EvaluateAsync(At(
            Syn("node", "10.20.31.50", 102), 0))).Matched);

        var windowsFlood = Rule("R731");
        for (var i = 0; i < 12; i++)
            Assert.False((await windowsFlood.EvaluateAsync(At(FloodTcp("python3"), i % 10))).Matched);

        var linuxFlood = Rule("R732");
        for (var i = 0; i < 12; i++)
            Assert.False((await linuxFlood.EvaluateAsync(At(FloodUdp("powershell.exe"), i % 10))).Matched);

        Assert.False((await Rule("R733").EvaluateAsync(At(
            Tls("osascript", "github.com"), 0))).Matched);

        var genericMacTls = Rule("R734");
        for (var i = 0; i < 4; i++)
            Assert.False((await genericMacTls.EvaluateAsync(At(
                Tls("python3", "pastebin.com"), i))).Matched);

        Assert.False((await Rule("R735").EvaluateAsync(At(
            Tls("hostd", "updates.vendor.example", port: 443), 0))).Matched);
    }

    [Theory]
    [InlineData("R726")][InlineData("R727")][InlineData("R728")][InlineData("R729")][InlineData("R730")]
    [InlineData("R731")][InlineData("R732")][InlineData("R733")][InlineData("R734")][InlineData("R735")]
    public void RegistryContainsExactlyOneCandidateShadowRule(string id)
    {
        var found = Assert.Single(RuleRegistry.CreateDefaultRules().Where(x => x.Descriptor.RuleId == id));
        var precision = Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(found);
        Assert.Equal(RulePrecisionMaturity.Candidate, precision.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow, precision.PrecisionProfile.DefaultMode);
    }

    [Fact]
    public void RegistryHasNoDuplicateRuleIds()
    {
        var rules = RuleRegistry.CreateDefaultRules();
        Assert.Equal(
            rules.Count,
            rules.Select(x => x.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }
}
