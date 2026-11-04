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

public sealed class R716R725AdvancedAccuracyBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 4, 13, 0, 0, DateTimeKind.Utc);

    private static IDetectionRule Rule(string id) => id switch
    {
        "R716" => new R716_SiprotecDiagnosticUdpFanoutRule(),
        "R717" => new R717_ScriptProcessCodeRepositoryApiPostRule(),
        "R718" => new R718_UnusualProcessCloudStorageTlsPayloadBurstRule(),
        "R719" => new R719_PowerShellExternalSmbPayloadBurstRule(),
        "R720" => new R720_WmicExternalXslHttpFetchRule(),
        "R721" => new R721_HybridConnectionManagerServiceBusTlsRule(),
        "R722" => new R722_BitsadminSuspiciousExtensionHttpGetRule(),
        "R723" => new R723_ScriptProcessDirectExternalHighEntropyDnsRule(),
        "R724" => new R724_NetworkUtilityPublicIpDiscoveryServiceRule(),
        "R725" => new R725_CurlWgetBrowserUserAgentHttpGetRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static RuleEvaluationContext At(TrafficRecord r, int seconds)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    private static TrafficRecord Udp50000(string destination)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "10.1.2.10",
            Destination = destination,
            IpVersion = 4,
            Protocol = "UDP",
            IsTcp = false,
            IsUdp = true,
            SourcePort = 35000,
            DestinationPort = 50000,
            L4Len = 18,
            Length = 46,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord Http(
        string process,
        string host,
        string uri,
        string method = "GET",
        string? userAgent = null)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "10.1.2.20",
            Destination = "8.8.8.8",
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            IsUdp = false,
            SourcePort = 52001,
            DestinationPort = 80,
            L4Len = 320,
            Length = 360,
            ApplicationProtocol = "HTTP",
            HttpMethod = method,
            HttpUri = uri,
            HttpHost = host,
            HttpUserAgent = userAgent ?? "Tool/1.0",
            HttpRequestHeaders = "Host: " + host + "\r\n",
            ProcessName = process,
            ProcessId = 4100,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord Tls(string process, string sni, int l4 = 1800)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "10.1.2.20",
            Destination = "8.8.8.8",
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            IsUdp = false,
            SourcePort = 52002,
            DestinationPort = 443,
            L4Len = l4,
            Length = l4 + 40,
            TlsVersion = "TLS1.3",
            Sni = sni,
            ProcessName = process,
            ProcessId = 4200,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord Smb(string process, int l4 = 240)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "10.1.2.20",
            Destination = "8.8.8.8",
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            IsUdp = false,
            SourcePort = 52003,
            DestinationPort = 445,
            TcpFlags = 0x18,
            L4Len = l4,
            Length = l4 + 40,
            ApplicationProtocol = "smb2",
            ProcessName = process,
            ProcessId = 4300,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord Dns(string process, string qname, string destination = "8.8.8.8")
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "10.1.2.20",
            Destination = destination,
            IpVersion = 4,
            Protocol = "UDP",
            IsTcp = false,
            IsUdp = true,
            SourcePort = 53000,
            DestinationPort = 53,
            L4Len = 80,
            Length = 108,
            ApplicationProtocol = "DNS",
            ApplicationService = "DNS",
            DnsQname = qname,
            DnsQtype = "TXT",
            DnsIsResponse = false,
            ProcessName = process,
            ProcessId = 4400,
            Info = "RAW-SECRET-MARKER"
        };

    private static string HighEntropyName()
        => "a1b2c3d4e5f6g7h8i9j0k1l2m3n4.example.test";

    private static TrafficRecord SinglePositive(string id) => id switch
    {
        "R717" => Http("powershell.exe", "api.github.com",
            "/repos/acme/private/releases?token=VERY-PRIVATE", "POST"),
        "R720" => Http("wmic.exe", "files.example",
            "/format/render.xsl?token=VERY-PRIVATE"),
        "R721" => Tls("hybridconnectionmanager.exe",
            "namespace.servicebus.windows.net"),
        "R722" => Http("bitsadmin.exe", "downloads.example",
            "/packages/update.ps1?token=VERY-PRIVATE"),
        "R723" => Dns("powershell.exe", HighEntropyName()),
        "R724" => Http("curl.exe", "api.ipify.org", "/ip"),
        "R725" => Http("curl.exe", "example.com", "/health",
            userAgent: "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, int start)
    {
        switch (id)
        {
            case "R716":
                await rule.EvaluateAsync(At(Udp50000("10.1.2.20"), start));
                return await rule.EvaluateAsync(At(Udp50000("10.1.3.20"), start + 1));

            case "R717":
                return await rule.EvaluateAsync(At(
                    Http("powershell.exe", "api.github.com", "/repos/acme/private/releases?token=VERY-PRIVATE", "POST"),
                    start));

            case "R718":
                for (var i = 0; i < 3; i++)
                    await rule.EvaluateAsync(At(Tls("powershell.exe", "content.dropboxapi.com"), start + i));
                return await rule.EvaluateAsync(At(Tls("powershell.exe", "content.dropboxapi.com"), start + 3));

            case "R719":
                await rule.EvaluateAsync(At(Smb("powershell.exe"), start));
                await rule.EvaluateAsync(At(Smb("powershell.exe"), start + 1));
                return await rule.EvaluateAsync(At(Smb("powershell.exe"), start + 2));

            case "R720":
                return await rule.EvaluateAsync(At(
                    Http("wmic.exe", "files.example", "/format/render.xsl?token=VERY-PRIVATE"),
                    start));

            case "R721":
                return await rule.EvaluateAsync(At(
                    Tls("hybridconnectionmanager.exe", "namespace.servicebus.windows.net"),
                    start));

            case "R722":
                return await rule.EvaluateAsync(At(
                    Http("bitsadmin.exe", "downloads.example", "/packages/update.ps1?token=VERY-PRIVATE"),
                    start));

            case "R723":
                return await rule.EvaluateAsync(At(
                    Dns("powershell.exe", HighEntropyName()),
                    start));

            case "R724":
                return await rule.EvaluateAsync(At(
                    Http("curl.exe", "api.ipify.org", "/ip"),
                    start));

            case "R725":
                return await rule.EvaluateAsync(At(
                    Http("curl.exe", "example.com", "/health",
                        userAgent: "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"),
                    start));

            default:
                throw new ArgumentOutOfRangeException(nameof(id));
        }
    }

    private static async Task<RuleEvaluationResult> NearMiss(IDetectionRule rule, string id)
    {
        switch (id)
        {
            case "R716":
                await rule.EvaluateAsync(At(Udp50000("10.1.2.20"), 0));
                return await rule.EvaluateAsync(At(Udp50000("10.1.2.20"), 1));

            case "R717":
                return await rule.EvaluateAsync(At(
                    Http("git.exe", "api.github.com", "/repos/acme/private/releases", "POST"), 0));

            case "R718":
                for (var i = 0; i < 3; i++)
                    await rule.EvaluateAsync(At(Tls("chrome.exe", "content.dropboxapi.com"), i));
                return await rule.EvaluateAsync(At(Tls("chrome.exe", "content.dropboxapi.com"), 3));

            case "R719":
                await rule.EvaluateAsync(At(Smb("chrome.exe"), 0));
                await rule.EvaluateAsync(At(Smb("chrome.exe"), 1));
                return await rule.EvaluateAsync(At(Smb("chrome.exe"), 2));

            case "R720":
                return await rule.EvaluateAsync(At(Http("wmic.exe", "files.example", "/format/render.xml"), 0));

            case "R721":
                return await rule.EvaluateAsync(At(Tls("svchost.exe", "namespace.servicebus.windows.net"), 0));

            case "R722":
                return await rule.EvaluateAsync(At(Http("bitsadmin.exe", "downloads.example", "/docs/readme.pdf"), 0));

            case "R723":
                return await rule.EvaluateAsync(At(Dns("powershell.exe", "update.microsoft.com"), 0));

            case "R724":
                return await rule.EvaluateAsync(At(Http("curl.exe", "example.com", "/ip"), 0));

            case "R725":
                return await rule.EvaluateAsync(At(
                    Http("curl.exe", "example.com", "/health", userAgent: "curl/8.0"), 0));

            default:
                throw new ArgumentOutOfRangeException(nameof(id));
        }
    }

    private static async Task<RuleEvaluationResult> MissingTelemetry(IDetectionRule rule, string id)
    {
        switch (id)
        {
            case "R716":
            {
                await rule.EvaluateAsync(At(Udp50000("10.1.2.20"), 0));
                var second = Udp50000("10.1.3.20");
                second.L4Len = null;
                return await rule.EvaluateAsync(At(second, 1));
            }

            case "R717":
            {
                var r = Http("powershell.exe", "api.github.com", "/repos/acme/private/releases", "POST");
                r.ApplicationProtocol = null;
                return await rule.EvaluateAsync(At(r, 0));
            }

            case "R718":
            {
                var r = Tls("powershell.exe", "content.dropboxapi.com");
                r.TlsVersion = null;
                return await rule.EvaluateAsync(At(r, 0));
            }

            case "R719":
            {
                var r = Smb("powershell.exe");
                r.ProcessId = 0;
                return await rule.EvaluateAsync(At(r, 0));
            }

            case "R720":
            {
                var r = Http("wmic.exe", "files.example", "/format/render.xsl");
                r.ProcessId = 0;
                return await rule.EvaluateAsync(At(r, 0));
            }

            case "R721":
            {
                var r = Tls("hybridconnectionmanager.exe", "namespace.servicebus.windows.net");
                r.Sni = null;
                return await rule.EvaluateAsync(At(r, 0));
            }

            case "R722":
            {
                var r = Http("bitsadmin.exe", "downloads.example", "/packages/update.ps1");
                r.HttpUri = null;
                return await rule.EvaluateAsync(At(r, 0));
            }

            case "R723":
            {
                var r = Dns("powershell.exe", HighEntropyName());
                r.ApplicationService = null;
                return await rule.EvaluateAsync(At(r, 0));
            }

            case "R724":
            {
                var r = Http("curl.exe", "api.ipify.org", "/ip");
                r.ProcessId = 0;
                return await rule.EvaluateAsync(At(r, 0));
            }

            case "R725":
            {
                var r = Http("curl.exe", "example.com", "/health",
                    userAgent: "Mozilla/5.0 Chrome/120.0 Safari/537.36");
                r.HttpUserAgent = null;
                return await rule.EvaluateAsync(At(r, 0));
            }

            default:
                throw new ArgumentOutOfRangeException(nameof(id));
        }
    }

    private static async Task<RuleEvaluationResult> Contradictory(IDetectionRule rule, string id)
    {
        TrafficRecord r = id switch
        {
            "R716" => Udp50000("10.1.2.20"),
            "R717" => Http("powershell.exe", "api.github.com", "/repos/acme/private/releases", "POST"),
            "R718" => Tls("powershell.exe", "content.dropboxapi.com"),
            "R719" => Smb("powershell.exe"),
            "R720" => Http("wmic.exe", "files.example", "/format/render.xsl"),
            "R721" => Tls("hybridconnectionmanager.exe", "namespace.servicebus.windows.net"),
            "R722" => Http("bitsadmin.exe", "downloads.example", "/packages/update.ps1"),
            "R723" => Dns("powershell.exe", HighEntropyName()),
            "R724" => Http("curl.exe", "api.ipify.org", "/ip"),
            "R725" => Http("curl.exe", "example.com", "/health",
                userAgent: "Mozilla/5.0 Chrome/120.0 Safari/537.36"),
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };

        if (r.IsUdp)
            r.IsTcp = true;
        else
            r.IsUdp = true;

        return await rule.EvaluateAsync(At(r, 0));
    }

    [Theory]
    [InlineData("R716")][InlineData("R717")][InlineData("R718")][InlineData("R719")][InlineData("R720")]
    [InlineData("R721")][InlineData("R722")][InlineData("R723")][InlineData("R724")][InlineData("R725")]
    public async Task PositiveRealLifeShapeMatchesAndEvidenceIsRedacted(string id)
    {
        var result = await Trigger(Rule(id), id, 0);
        Assert.True(result.Matched);

        var evt = Assert.Single(result.Events);
        var json = JsonSerializer.Serialize(evt);
        Assert.Contains("workbook.R", json);
        Assert.DoesNotContain("RAW-SECRET-MARKER", json);
        Assert.DoesNotContain("VERY-PRIVATE", json);
        Assert.DoesNotContain(HighEntropyName().ToLowerInvariant(), json.ToLowerInvariant());
    }

    [Theory]
    [InlineData("R716")][InlineData("R717")][InlineData("R718")][InlineData("R719")][InlineData("R720")]
    [InlineData("R721")][InlineData("R722")][InlineData("R723")][InlineData("R724")][InlineData("R725")]
    public async Task BenignNearMissMissingTelemetryAndContradictoryFieldsDoNotMatch(string id)
    {
        Assert.False((await NearMiss(Rule(id), id)).Matched);
        Assert.False((await MissingTelemetry(Rule(id), id)).Matched);
        Assert.False((await Contradictory(Rule(id), id)).Matched);
    }

    [Fact]
    public async Task StatefulWindowsRejectDuplicateOutOfOrderAndExpiredEvidence()
    {
        // R716: duplicate packet ID cannot supply the second distinct target.
        var r716 = Rule("R716");
        var u1 = Udp50000("10.1.2.20");
        var u2 = Udp50000("10.1.3.20");
        u2.Id = u1.Id;
        await r716.EvaluateAsync(At(u1, 0));
        Assert.False((await r716.EvaluateAsync(At(u2, 1))).Matched);

        var r716Reverse = Rule("R716");
        await r716Reverse.EvaluateAsync(At(Udp50000("10.1.2.20"), 10));
        Assert.False((await r716Reverse.EvaluateAsync(At(Udp50000("10.1.3.20"), 9))).Matched);

        var r716Expired = Rule("R716");
        await r716Expired.EvaluateAsync(At(Udp50000("10.1.2.20"), 0));
        Assert.False((await r716Expired.EvaluateAsync(At(Udp50000("10.1.3.20"), 61))).Matched);

        // R718: four observations are required inside the two-minute window.
        var r718 = Rule("R718");
        var t1 = Tls("powershell.exe", "content.dropboxapi.com");
        await r718.EvaluateAsync(At(t1, 0));
        var t2 = Tls("powershell.exe", "content.dropboxapi.com"); t2.Id = t1.Id;
        Assert.False((await r718.EvaluateAsync(At(t2, 1))).Matched);
        Assert.False((await r718.EvaluateAsync(At(Tls("powershell.exe", "content.dropboxapi.com"), 2))).Matched);
        Assert.False((await r718.EvaluateAsync(At(Tls("powershell.exe", "content.dropboxapi.com"), 3))).Matched);

        var r718Expired = Rule("R718");
        await r718Expired.EvaluateAsync(At(Tls("powershell.exe", "content.dropboxapi.com"), 0));
        await r718Expired.EvaluateAsync(At(Tls("powershell.exe", "content.dropboxapi.com"), 1));
        await r718Expired.EvaluateAsync(At(Tls("powershell.exe", "content.dropboxapi.com"), 2));
        Assert.False((await r718Expired.EvaluateAsync(At(Tls("powershell.exe", "content.dropboxapi.com"), 121))).Matched);

        // R719: stale and reverse-time observations cannot complete the burst.
        var r719Reverse = Rule("R719");
        await r719Reverse.EvaluateAsync(At(Smb("powershell.exe"), 10));
        Assert.False((await r719Reverse.EvaluateAsync(At(Smb("powershell.exe"), 9))).Matched);

        var r719Expired = Rule("R719");
        await r719Expired.EvaluateAsync(At(Smb("powershell.exe"), 0));
        await r719Expired.EvaluateAsync(At(Smb("powershell.exe"), 1));
        Assert.False((await r719Expired.EvaluateAsync(At(Smb("powershell.exe"), 121))).Matched);
    }

    [Theory]
    [InlineData("R716")][InlineData("R717")][InlineData("R718")][InlineData("R719")][InlineData("R720")]
    [InlineData("R721")][InlineData("R722")][InlineData("R723")][InlineData("R724")][InlineData("R725")]
    public async Task EveryRuleOwnsReplayAndCooldownState(string id)
    {
        var rule = Rule(id);

        Assert.True((await Trigger(rule, id, 0)).Matched);

        var second = await Trigger(rule, id, 20);
        Assert.True(second.Suppressed);
        Assert.Empty(second.Events);

        Assert.True((await Trigger(rule, id, 620)).Matched);
    }

    [Theory]
    [InlineData("R717")][InlineData("R720")][InlineData("R721")][InlineData("R722")]
    [InlineData("R723")][InlineData("R724")][InlineData("R725")]
    public async Task SingleEventRulesRejectDuplicatePacketIdAndReverseTime(string id)
    {
        var rule = Rule(id);
        var record = SinglePositive(id);

        Assert.True((await rule.EvaluateAsync(At(record, 10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(record, 11))).Matched);

        var earlier = SinglePositive(id);
        Assert.False((await rule.EvaluateAsync(At(earlier, 9))).Matched);
    }

    [Fact]
    public async Task NeighboringRulesRemainNonConverged()
    {
        // R717 is repository API POST only; a Git smart-HTTP push path is not its predicate.
        Assert.False((await Rule("R717").EvaluateAsync(At(
            Http("powershell.exe", "github.com", "/acme/repo.git/git-receive-pack", "POST"), 0))).Matched);

        // R721 is TLS Service Bus contact, while R629 remains DNS-only.
        Assert.False((await Rule("R721").EvaluateAsync(At(
            Dns("hybridconnectionmanager.exe", "namespace.servicebus.windows.net"), 0))).Matched);

        // R722 owns Bitsadmin extension downloads; WMIC XSL is a separate R720 identity.
        Assert.False((await Rule("R722").EvaluateAsync(At(
            Http("wmic.exe", "downloads.example", "/payload/update.ps1"), 0))).Matched);

        // R724 public-IP discovery does not subsume the R725 browser-UA mismatch.
        Assert.False((await Rule("R724").EvaluateAsync(At(
            Http("curl.exe", "example.com", "/health",
                userAgent: "Mozilla/5.0 Chrome/120.0 Safari/537.36"), 0))).Matched);

        // R718 cloud TLS requires cloud SNI and an unusual process; raw SMB remains R719.
        var cloud = Rule("R718");
        await cloud.EvaluateAsync(At(Smb("powershell.exe"), 0));
        await cloud.EvaluateAsync(At(Smb("powershell.exe"), 1));
        await cloud.EvaluateAsync(At(Smb("powershell.exe"), 2));
        Assert.False((await cloud.EvaluateAsync(At(Smb("powershell.exe"), 3))).Matched);
    }

    [Theory]
    [InlineData("R716")][InlineData("R717")][InlineData("R718")][InlineData("R719")][InlineData("R720")]
    [InlineData("R721")][InlineData("R722")][InlineData("R723")][InlineData("R724")][InlineData("R725")]
    public void RegistryContainsExactlyOneCandidateShadow(string id)
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
