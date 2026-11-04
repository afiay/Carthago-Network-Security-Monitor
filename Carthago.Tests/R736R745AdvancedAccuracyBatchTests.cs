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

public sealed class R736R745AdvancedAccuracyBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 4, 15, 0, 0, DateTimeKind.Utc);

    private static IDetectionRule Rule(string id) => id switch
    {
        "R736" => new R736_LinuxNonBrowserTlsPayloadBurstRule(),
        "R737" => new R737_LinuxCliLargeHttpPostBurstRule(),
        "R738" => new R738_LinuxRecurrentTransferCadenceRule(),
        "R739" => new R739_LinuxScriptHttpRequestFloodRule(),
        "R740" => new R740_MacOsUtilityLargeHttpPostBurstRule(),
        "R741" => new R741_HypervisorProcessDeadDropTlsContactRule(),
        "R742" => new R742_BusyBoxCliWebHeartbeatCadenceRule(),
        "R743" => new R743_EsxiManagementProcessFixedSizeEgressCadenceRule(),
        "R744" => new R744_EsxiManagementProcessProxyPortFanoutRule(),
        "R745" => new R745_HpingNpingPublicTargetFanoutRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static RuleEvaluationContext At(TrafficRecord r, double seconds)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    private static TrafficRecord Tls(
        string process,
        string sni,
        int l4 = 1600,
        int pid = 6100)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "10.30.40.50",
            Destination = "8.8.8.8",
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            IsUdp = false,
            IsQuic = false,
            SourcePort = 52000,
            DestinationPort = 443,
            TcpFlags = 0x18,
            L4Len = l4,
            Length = l4 + 40,
            TlsVersion = "TLS1.3",
            Sni = sni,
            ProcessName = process,
            ProcessId = pid,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord Http(
        string process,
        string method,
        string host,
        string uri,
        int l4 = 1600,
        int pid = 6200)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "10.30.40.50",
            Destination = "8.8.4.4",
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            IsUdp = false,
            IsQuic = false,
            SourcePort = 52001,
            DestinationPort = 80,
            TcpFlags = 0x18,
            L4Len = l4,
            Length = l4 + 40,
            ApplicationProtocol = "HTTP",
            HttpMethod = method,
            HttpUri = uri,
            HttpHost = host,
            HttpUserAgent = "tool/1.0",
            HttpRequestHeaders = "Host: " + host + "\r\n",
            ProcessName = process,
            ProcessId = pid,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord RawPayload(
        string process,
        string destination = "8.8.4.4",
        int port = 873,
        int l4 = 900,
        int pid = 6300)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "10.30.40.50",
            Destination = destination,
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            IsUdp = false,
            IsQuic = false,
            SourcePort = 52002,
            DestinationPort = port,
            TcpFlags = 0x18,
            L4Len = l4,
            Length = l4 + 40,
            ProcessName = process,
            ProcessId = pid,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord Syn(
        string process,
        string destination,
        int port,
        int pid = 6400)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "10.30.40.50",
            Destination = destination,
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            IsUdp = false,
            IsQuic = false,
            SourcePort = 52003,
            DestinationPort = port,
            TcpFlags = 0x02,
            L4Len = null,
            Length = 40,
            ProcessName = process,
            ProcessId = pid,
            Info = "RAW-SECRET-MARKER"
        };

    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, double start)
    {
        switch (id)
        {
            case "R736":
                for (var i = 0; i < 3; i++)
                    await rule.EvaluateAsync(At(Tls("python3", "transfer.example", 1600), start + i));
                return await rule.EvaluateAsync(At(Tls("python3", "transfer.example", 1600), start + 3));

            case "R737":
                for (var i = 0; i < 3; i++)
                    await rule.EvaluateAsync(At(Http("curl", "POST", "upload.example",
                        "/api/upload?token=VERY-PRIVATE", 1600), start + i));
                return await rule.EvaluateAsync(At(Http("curl", "POST", "upload.example",
                    "/api/upload?token=VERY-PRIVATE", 1600), start + 3));

            case "R738":
                await rule.EvaluateAsync(At(RawPayload("rsync", l4: 900), start));
                await rule.EvaluateAsync(At(RawPayload("rsync", l4: 920), start + 30));
                return await rule.EvaluateAsync(At(RawPayload("rsync", l4: 910), start + 60));

            case "R739":
                for (var i = 0; i < 11; i++)
                    await rule.EvaluateAsync(At(Http("python3", "GET", "api.example",
                        "/resource?token=VERY-PRIVATE", 220), start + i * 0.8));
                return await rule.EvaluateAsync(At(Http("python3", "GET", "api.example",
                    "/resource?token=VERY-PRIVATE", 220), start + 8.8));

            case "R740":
                for (var i = 0; i < 3; i++)
                    await rule.EvaluateAsync(At(Http("osascript", "PUT", "forms.example",
                        "/documents/upload?token=VERY-PRIVATE", 1600), start + i));
                return await rule.EvaluateAsync(At(Http("osascript", "PUT", "forms.example",
                    "/documents/upload?token=VERY-PRIVATE", 1600), start + 3));

            case "R741":
                return await rule.EvaluateAsync(At(Tls("hostd", "pastebin.com", 220), start));

            case "R742":
                await rule.EvaluateAsync(At(Tls("wget", "api.vendor.example", 260), start));
                await rule.EvaluateAsync(At(Tls("wget", "api.vendor.example", 270), start + 15));
                return await rule.EvaluateAsync(At(Tls("wget", "api.vendor.example", 265), start + 30));

            case "R743":
                await rule.EvaluateAsync(At(RawPayload("hostd", port: 4444, l4: 300), start));
                await rule.EvaluateAsync(At(RawPayload("hostd", port: 4444, l4: 304), start + 15));
                return await rule.EvaluateAsync(At(RawPayload("hostd", port: 4444, l4: 302), start + 30));

            case "R744":
                await rule.EvaluateAsync(At(Syn("hostd", "8.8.8.8", 8080), start));
                await rule.EvaluateAsync(At(Syn("hostd", "1.1.1.1", 8080), start + 1));
                return await rule.EvaluateAsync(At(Syn("hostd", "9.9.9.9", 8080), start + 2));

            case "R745":
                await rule.EvaluateAsync(At(Syn("hping3", "8.8.8.8", 80), start));
                await rule.EvaluateAsync(At(Syn("hping3", "1.1.1.1", 80), start + 1));
                await rule.EvaluateAsync(At(Syn("hping3", "9.9.9.9", 80), start + 2));
                return await rule.EvaluateAsync(At(Syn("hping3", "4.2.2.2", 80), start + 3));

            default:
                throw new ArgumentOutOfRangeException(nameof(id));
        }
    }

    private static async Task<RuleEvaluationResult> NearMiss(IDetectionRule rule, string id)
    {
        switch (id)
        {
            case "R736":
                for (var i = 0; i < 4; i++)
                    Assert.False((await rule.EvaluateAsync(At(Tls("chrome.exe", "transfer.example"), i))).Matched);
                return await rule.EvaluateAsync(At(Tls("chrome.exe", "transfer.example"), 4));

            case "R737":
                return await rule.EvaluateAsync(At(Http("curl", "GET", "upload.example", "/api/upload", 1600), 0));

            case "R738":
                await rule.EvaluateAsync(At(RawPayload("rsync", l4: 900), 0));
                await rule.EvaluateAsync(At(RawPayload("rsync", l4: 1500), 30));
                return await rule.EvaluateAsync(At(RawPayload("rsync", l4: 900), 60));

            case "R739":
                for (var i = 0; i < 12; i++)
                    Assert.False((await rule.EvaluateAsync(At(Http("chrome.exe", "GET", "api.example", "/resource", 220), i * 0.8))).Matched);
                return await rule.EvaluateAsync(At(Http("chrome.exe", "GET", "api.example", "/resource", 220), 10));

            case "R740":
                return await rule.EvaluateAsync(At(Http("curl", "POST", "forms.example", "/documents/upload", 1600), 0));

            case "R741":
                return await rule.EvaluateAsync(At(Tls("hostd", "github.com", 220), 0));

            case "R742":
                await rule.EvaluateAsync(At(Tls("wget", "pastebin.com", 260), 0));
                await rule.EvaluateAsync(At(Tls("wget", "pastebin.com", 260), 15));
                return await rule.EvaluateAsync(At(Tls("wget", "pastebin.com", 260), 30));

            case "R743":
                await rule.EvaluateAsync(At(RawPayload("hostd", port: 443, l4: 300), 0));
                await rule.EvaluateAsync(At(RawPayload("hostd", port: 443, l4: 300), 15));
                return await rule.EvaluateAsync(At(RawPayload("hostd", port: 443, l4: 300), 30));

            case "R744":
                await rule.EvaluateAsync(At(Syn("hostd", "8.8.8.8", 8080), 0));
                await rule.EvaluateAsync(At(Syn("hostd", "8.8.8.8", 8080), 1));
                return await rule.EvaluateAsync(At(Syn("hostd", "8.8.8.8", 8080), 2));

            case "R745":
                await rule.EvaluateAsync(At(Syn("curl", "8.8.8.8", 80), 0));
                await rule.EvaluateAsync(At(Syn("curl", "1.1.1.1", 80), 1));
                await rule.EvaluateAsync(At(Syn("curl", "9.9.9.9", 80), 2));
                return await rule.EvaluateAsync(At(Syn("curl", "4.2.2.2", 80), 3));

            default:
                throw new ArgumentOutOfRangeException(nameof(id));
        }
    }

    private static async Task<RuleEvaluationResult> MissingTelemetry(IDetectionRule rule, string id)
    {
        TrafficRecord r = id switch
        {
            "R736" => Tls("python3", "transfer.example"),
            "R737" => Http("curl", "POST", "upload.example", "/api/upload", 1600),
            "R738" => RawPayload("rsync"),
            "R739" => Http("python3", "GET", "api.example", "/resource", 220),
            "R740" => Http("osascript", "PUT", "forms.example", "/documents/upload", 1600),
            "R741" => Tls("hostd", "pastebin.com", 220),
            "R742" => Tls("wget", "api.vendor.example", 260),
            "R743" => RawPayload("hostd", port: 4444, l4: 300),
            "R744" => Syn("hostd", "8.8.8.8", 8080),
            "R745" => Syn("hping3", "8.8.8.8", 80),
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };
        r.ProcessId = 0;
        return await rule.EvaluateAsync(At(r, 0));
    }

    private static async Task<RuleEvaluationResult> Contradictory(IDetectionRule rule, string id)
    {
        TrafficRecord r = id switch
        {
            "R736" => Tls("python3", "transfer.example"),
            "R737" => Http("curl", "POST", "upload.example", "/api/upload", 1600),
            "R738" => RawPayload("rsync"),
            "R739" => Http("python3", "GET", "api.example", "/resource", 220),
            "R740" => Http("osascript", "PUT", "forms.example", "/documents/upload", 1600),
            "R741" => Tls("hostd", "pastebin.com", 220),
            "R742" => Tls("wget", "api.vendor.example", 260),
            "R743" => RawPayload("hostd", port: 4444, l4: 300),
            "R744" => Syn("hostd", "8.8.8.8", 8080),
            "R745" => Syn("hping3", "8.8.8.8", 80),
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };
        r.IsUdp = true;
        return await rule.EvaluateAsync(At(r, 0));
    }

    [Theory]
    [InlineData("R736")][InlineData("R737")][InlineData("R738")][InlineData("R739")][InlineData("R740")]
    [InlineData("R741")][InlineData("R742")][InlineData("R743")][InlineData("R744")][InlineData("R745")]
    public async Task PositiveShapesMatchWithoutLeakingRawInfoOrQuery(string id)
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
    [InlineData("R736")][InlineData("R737")][InlineData("R738")][InlineData("R739")][InlineData("R740")]
    [InlineData("R741")][InlineData("R742")][InlineData("R743")][InlineData("R744")][InlineData("R745")]
    public async Task BenignNearMissMissingTelemetryAndContradictoryTransportDoNotMatch(string id)
    {
        Assert.False((await NearMiss(Rule(id), id)).Matched);
        Assert.False((await MissingTelemetry(Rule(id), id)).Matched);
        Assert.False((await Contradictory(Rule(id), id)).Matched);
    }

    [Fact]
    public async Task StatefulRulesRejectDuplicateReverseTimeAndExpiredSequences()
    {
        var r737 = Rule("R737");
        var p = Http("curl", "POST", "upload.example", "/api/upload", 1600);
        await r737.EvaluateAsync(At(p, 0));
        var duplicate = Http("curl", "POST", "upload.example", "/api/upload", 1600);
        duplicate.Id = p.Id;
        Assert.False((await r737.EvaluateAsync(At(duplicate, 1))).Matched);

        var r738 = Rule("R738");
        await r738.EvaluateAsync(At(RawPayload("rsync", l4: 900), 30));
        Assert.False((await r738.EvaluateAsync(At(RawPayload("rsync", l4: 900), 20))).Matched);

        var expired = Rule("R742");
        await expired.EvaluateAsync(At(Tls("wget", "api.vendor.example", 260), 0));
        await expired.EvaluateAsync(At(Tls("wget", "api.vendor.example", 260), 15));
        Assert.False((await expired.EvaluateAsync(At(Tls("wget", "api.vendor.example", 260), 130))).Matched);

        var fanout = Rule("R744");
        var s = Syn("hostd", "8.8.8.8", 8080);
        await fanout.EvaluateAsync(At(s, 0));
        var sameId = Syn("hostd", "1.1.1.1", 8080); sameId.Id = s.Id;
        Assert.False((await fanout.EvaluateAsync(At(sameId, 1))).Matched);

        var targetFanout = Rule("R745");
        await targetFanout.EvaluateAsync(At(Syn("hping3", "8.8.8.8", 80), 0));
        await targetFanout.EvaluateAsync(At(Syn("hping3", "1.1.1.1", 80), 1));
        await targetFanout.EvaluateAsync(At(Syn("hping3", "9.9.9.9", 80), 2));
        Assert.False((await targetFanout.EvaluateAsync(At(Syn("hping3", "4.2.2.2", 80), 11))).Matched);
    }

    [Theory]
    [InlineData("R736")][InlineData("R737")][InlineData("R738")][InlineData("R739")][InlineData("R740")]
    [InlineData("R741")][InlineData("R742")][InlineData("R743")][InlineData("R744")][InlineData("R745")]
    public async Task EachRuleOwnsCooldownAndRecovery(string id)
    {
        var rule = Rule(id);
        Assert.True((await Trigger(rule, id, 0)).Matched);
        var repeat = await Trigger(rule, id, 100);
        Assert.True(repeat.Suppressed);
        Assert.Empty(repeat.Events);
        Assert.True((await Trigger(rule, id, 700)).Matched);
    }

    [Fact]
    public async Task NewPredicatesRemainIndependentFromNeighboringFamilies()
    {
        // R737 does not become a generic FTP upload detector.
        Assert.False((await Rule("R737").EvaluateAsync(At(RawPayload("curl", port: 21), 0))).Matched);

        // R738 is cadence-specific and does not match isolated rsync traffic.
        Assert.False((await Rule("R738").EvaluateAsync(At(RawPayload("rsync"), 0))).Matched);

        // R741 owns hypervisor + dead-drop TLS only.
        Assert.False((await Rule("R741").EvaluateAsync(At(Tls("hostd", "api.vendor.example", 220), 0))).Matched);

        // R742 excludes dead-drop and common service families.
        var heartbeat = Rule("R742");
        await heartbeat.EvaluateAsync(At(Tls("wget", "pastebin.com", 260), 0));
        await heartbeat.EvaluateAsync(At(Tls("wget", "pastebin.com", 260), 15));
        Assert.False((await heartbeat.EvaluateAsync(At(Tls("wget", "pastebin.com", 260), 30))).Matched);

        // R743 does not absorb generic TLS/443 volume.
        var fixedCadence = Rule("R743");
        await fixedCadence.EvaluateAsync(At(Tls("hostd", "api.vendor.example", 300), 0));
        await fixedCadence.EvaluateAsync(At(Tls("hostd", "api.vendor.example", 300), 15));
        Assert.False((await fixedCadence.EvaluateAsync(At(Tls("hostd", "api.vendor.example", 300), 30))).Matched);

        // R745 exact hping/nping attribution differs from the generic Linux flood rule.
        var toolFanout = Rule("R745");
        await toolFanout.EvaluateAsync(At(Syn("python3", "8.8.8.8", 80), 0));
        await toolFanout.EvaluateAsync(At(Syn("python3", "1.1.1.1", 80), 1));
        await toolFanout.EvaluateAsync(At(Syn("python3", "9.9.9.9", 80), 2));
        Assert.False((await toolFanout.EvaluateAsync(At(Syn("python3", "4.2.2.2", 80), 3))).Matched);
    }

    [Theory]
    [InlineData("R736")][InlineData("R737")][InlineData("R738")][InlineData("R739")][InlineData("R740")]
    [InlineData("R741")][InlineData("R742")][InlineData("R743")][InlineData("R744")][InlineData("R745")]
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
