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

public sealed class R756R765AdvancedAccuracyBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 6, 18, 0, 0, DateTimeKind.Utc);
    private const string LocalHost = "10.60.70.20";

    private static IDetectionRule Rule(string id) => id switch
    {
        "R756" => new R756_EsxiManagementProcessCodeRepositoryTlsBurstRule(),
        "R757" => new R757_LlmnrNbnsConflictThenSmbRelayShapeRule(),
        "R758" => new R758_PublicUncommonTriggerThenReverseSynRule(),
        "R759" => new R759_LinuxVncProcessPublicSynAckRule(),
        "R760" => new R760_MacScriptBrowserUserAgentHttpRequestRule(),
        "R761" => new R761_RmmProcessExternalTlsCadenceRule(),
        "R762" => new R762_MsbuildExternalTlsPayloadBurstRule(),
        "R763" => new R763_EsxiStyleDnsTunnelShapeRule(),
        "R764" => new R764_LinuxDnsTunnelToolQueryBurstRule(),
        "R765" => new R765_LinuxRemoteServiceAttemptThenShellEgressRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static RuleEvaluationContext At(TrafficRecord r, double seconds)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    private static TrafficRecord Tls(
        string process,
        string sni,
        int l4 = 1600,
        int pid = 8100,
        string source = LocalHost,
        string destination = "8.8.8.8")
        => new()
        {
            Id = Guid.NewGuid(),
            Source = source,
            Destination = destination,
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

    private static TrafficRecord Syn(
        string source,
        string destination,
        int destinationPort,
        int sourcePort = 52001)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = source,
            Destination = destination,
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            IsUdp = false,
            IsQuic = false,
            SourcePort = sourcePort,
            DestinationPort = destinationPort,
            TcpFlags = 0x02,
            L4Len = null,
            Length = 40,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord VncSynAck(string process)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = LocalHost,
            Destination = "8.8.8.8",
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            IsUdp = false,
            IsQuic = false,
            SourcePort = 5900,
            DestinationPort = 53000,
            TcpFlags = 0x12,
            L4Len = null,
            Length = 40,
            ProcessName = process,
            ProcessId = 8200,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord Http(
        string process,
        string userAgent,
        string method = "GET",
        string uri = "/status?token=VERY-PRIVATE")
        => new()
        {
            Id = Guid.NewGuid(),
            Source = LocalHost,
            Destination = "8.8.4.4",
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            IsUdp = false,
            IsQuic = false,
            SourcePort = 52002,
            DestinationPort = 80,
            TcpFlags = 0x18,
            L4Len = 320,
            Length = 360,
            ApplicationProtocol = "HTTP",
            HttpMethod = method,
            HttpUri = uri,
            HttpHost = "api.example",
            HttpUserAgent = userAgent,
            HttpRequestHeaders = "Host: api.example\r\nUser-Agent: " + userAgent + "\r\n\r\n",
            ProcessName = process,
            ProcessId = 8300,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord Dns(
        string process,
        string qname,
        int pid = 8400)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = LocalHost,
            Destination = "8.8.8.8",
            IpVersion = 4,
            Protocol = "UDP",
            IsTcp = false,
            IsUdp = true,
            IsQuic = false,
            SourcePort = 53000,
            DestinationPort = 53,
            L4Len = 90,
            Length = 118,
            ApplicationProtocol = "DNS",
            ApplicationService = "DNS",
            DnsQname = qname,
            DnsQtype = "TXT",
            DnsIsResponse = false,
            ProcessName = process,
            ProcessId = pid,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord NameConflict(
        string responder = "10.60.70.66",
        string peer = LocalHost)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = responder,
            Destination = peer,
            IpVersion = 4,
            Protocol = "UDP",
            IsTcp = false,
            IsUdp = true,
            IsQuic = false,
            SourcePort = 5355,
            DestinationPort = 5355,
            TcpFlags = null,
            L4Len = 96,
            Length = 124,
            ApplicationProtocol = "LLMNR",
            ApplicationService = "CONFLICTING_RESPONSE",
            DnsQname = "fileserver",
            DnsQtype = "A",
            DnsIsResponse = true,
            DnsAnswers = "10.60.70.66",
            Info = "RAW-SECRET-MARKER"
        };

    private static string EncodedLabel(int seed)
        => seed switch
        {
            1 => "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
            2 => "b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7",
            _ => "c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
        };

    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, double start)
    {
        switch (id)
        {
            case "R756":
                for (var i = 0; i < 3; i++)
                    await rule.EvaluateAsync(At(Tls("hostd", "github.com"), start + i));
                return await rule.EvaluateAsync(At(Tls("hostd", "github.com"), start + 3));

            case "R757":
                await rule.EvaluateAsync(At(NameConflict(), start));
                return await rule.EvaluateAsync(At(Syn(LocalHost, "10.60.70.66", 445), start + 10));

            case "R758":
                await rule.EvaluateAsync(At(Syn("8.8.8.8", LocalHost, 41000), start));
                return await rule.EvaluateAsync(At(Syn(LocalHost, "8.8.8.8", 4444), start + 10));

            case "R759":
                return await rule.EvaluateAsync(At(VncSynAck("x11vnc"), start));

            case "R760":
                return await rule.EvaluateAsync(At(Http("osascript",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"), start));

            case "R761":
                await rule.EvaluateAsync(At(Tls("anydesk.exe", "relay.anydesk.example", 300), start));
                await rule.EvaluateAsync(At(Tls("anydesk.exe", "relay.anydesk.example", 320), start + 15));
                return await rule.EvaluateAsync(At(Tls("anydesk.exe", "relay.anydesk.example", 310), start + 30));

            case "R762":
                for (var i = 0; i < 3; i++)
                    await rule.EvaluateAsync(At(Tls("msbuild.exe", "packages.example"), start + i));
                return await rule.EvaluateAsync(At(Tls("msbuild.exe", "packages.example"), start + 3));

            case "R763":
                await rule.EvaluateAsync(At(Dns("busybox", EncodedLabel(1) + ".exfil.example"), start));
                await rule.EvaluateAsync(At(Dns("busybox", EncodedLabel(2) + ".exfil.example"), start + 1));
                return await rule.EvaluateAsync(At(Dns("busybox", EncodedLabel(3) + ".exfil.example"), start + 2));

            case "R764":
                await rule.EvaluateAsync(At(Dns("dnscat2", EncodedLabel(1) + ".tunnel.example"), start));
                await rule.EvaluateAsync(At(Dns("dnscat2", EncodedLabel(2) + ".tunnel.example"), start + 1));
                return await rule.EvaluateAsync(At(Dns("dnscat2", EncodedLabel(3) + ".tunnel.example"), start + 2));

            case "R765":
                await rule.EvaluateAsync(At(Syn("8.8.8.8", LocalHost, 22), start));
                return await rule.EvaluateAsync(At(Tls("bash", "callback.example", 300), start + 20));

            default:
                throw new ArgumentOutOfRangeException(nameof(id));
        }
    }

    private static async Task<RuleEvaluationResult> NearMiss(IDetectionRule rule, string id)
    {
        switch (id)
        {
            case "R756":
                for (var i = 0; i < 4; i++)
                    await rule.EvaluateAsync(At(Tls("hostd", "dropbox.com"), i));
                return await rule.EvaluateAsync(At(Tls("hostd", "dropbox.com"), 4));

            case "R757":
                await rule.EvaluateAsync(At(NameConflict(), 0));
                return await rule.EvaluateAsync(At(Syn("10.60.70.21", "10.60.70.66", 445), 10));

            case "R758":
                await rule.EvaluateAsync(At(Syn("8.8.8.8", LocalHost, 41000), 0));
                return await rule.EvaluateAsync(At(Syn(LocalHost, "1.1.1.1", 4444), 10));

            case "R759":
                return await rule.EvaluateAsync(At(VncSynAck("sshd"), 0));

            case "R760":
                return await rule.EvaluateAsync(At(Http("osascript",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"), 0));

            case "R761":
                await rule.EvaluateAsync(At(Tls("anydesk.exe", "relay.anydesk.example", 300), 0));
                await rule.EvaluateAsync(At(Tls("anydesk.exe", "relay.anydesk.example", 700), 15));
                return await rule.EvaluateAsync(At(Tls("anydesk.exe", "relay.anydesk.example", 300), 30));

            case "R762":
                for (var i = 0; i < 4; i++)
                    await rule.EvaluateAsync(At(Tls("dotnet.exe", "packages.example"), i));
                return await rule.EvaluateAsync(At(Tls("dotnet.exe", "packages.example"), 4));

            case "R763":
                await rule.EvaluateAsync(At(Dns("busybox", "updates.vendor.example"), 0));
                await rule.EvaluateAsync(At(Dns("busybox", "updates.vendor.example"), 1));
                return await rule.EvaluateAsync(At(Dns("busybox", "updates.vendor.example"), 2));

            case "R764":
                await rule.EvaluateAsync(At(Dns("curl", EncodedLabel(1) + ".tunnel.example"), 0));
                await rule.EvaluateAsync(At(Dns("curl", EncodedLabel(2) + ".tunnel.example"), 1));
                return await rule.EvaluateAsync(At(Dns("curl", EncodedLabel(3) + ".tunnel.example"), 2));

            case "R765":
                await rule.EvaluateAsync(At(Syn("8.8.8.8", LocalHost, 5900), 0));
                return await rule.EvaluateAsync(At(Tls("bash", "callback.example", 300), 20));

            default:
                throw new ArgumentOutOfRangeException(nameof(id));
        }
    }

    [Theory]
    [InlineData("R756")][InlineData("R757")][InlineData("R758")][InlineData("R759")][InlineData("R760")]
    [InlineData("R761")][InlineData("R762")][InlineData("R763")][InlineData("R764")][InlineData("R765")]
    public async Task PositiveShapesMatchAndEvidenceDoesNotLeakRawData(string id)
    {
        var result = await Trigger(Rule(id), id, 0);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        var json = JsonSerializer.Serialize(evt);
        Assert.Contains("workbook.R", json);
        Assert.DoesNotContain("RAW-SECRET-MARKER", json);
        Assert.DoesNotContain("VERY-PRIVATE", json);
        var lower = json.ToLowerInvariant();
        Assert.DoesNotContain(EncodedLabel(1).ToLowerInvariant(), lower);
        Assert.DoesNotContain(EncodedLabel(2).ToLowerInvariant(), lower);
        Assert.DoesNotContain(EncodedLabel(3).ToLowerInvariant(), lower);
    }

    [Theory]
    [InlineData("R756")][InlineData("R757")][InlineData("R758")][InlineData("R759")][InlineData("R760")]
    [InlineData("R761")][InlineData("R762")][InlineData("R763")][InlineData("R764")][InlineData("R765")]
    public async Task RuleSpecificBenignNearMissDoesNotMatch(string id)
        => Assert.False((await NearMiss(Rule(id), id)).Matched);

    [Fact]
    public async Task ProcessGatedRulesRequireLocalAttribution()
    {
        foreach (var id in new[] { "R756", "R759", "R760", "R761", "R762", "R763", "R764" })
        {
            IDetectionRule rule = Rule(id);
            TrafficRecord record = id switch
            {
                "R756" => Tls("hostd", "github.com"),
                "R759" => VncSynAck("x11vnc"),
                "R760" => Http("osascript",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"),
                "R761" => Tls("anydesk.exe", "relay.anydesk.example", 300),
                "R762" => Tls("msbuild.exe", "packages.example"),
                "R763" => Dns("busybox", EncodedLabel(1) + ".exfil.example"),
                "R764" => Dns("dnscat2", EncodedLabel(1) + ".tunnel.example"),
                _ => throw new ArgumentOutOfRangeException()
            };
            record.ProcessId = 0;
            Assert.False((await rule.EvaluateAsync(At(record, 0))).Matched);
        }

        var r765 = Rule("R765");
        await r765.EvaluateAsync(At(Syn("8.8.8.8", LocalHost, 22), 0));
        var follow = Tls("bash", "callback.example", 300);
        follow.ProcessId = 0;
        Assert.False((await r765.EvaluateAsync(At(follow, 20))).Matched);
    }

    [Fact]
    public async Task ContradictoryTransportFailsClosed()
    {
        var r756 = Rule("R756");
        for (var i = 0; i < 4; i++)
        {
            var x = Tls("hostd", "github.com"); x.IsUdp = true;
            Assert.False((await r756.EvaluateAsync(At(x, i))).Matched);
        }

        var r757 = Rule("R757");
        var conflict = NameConflict(); conflict.IsTcp = true;
        Assert.False((await r757.EvaluateAsync(At(conflict, 0))).Matched);
        Assert.False((await r757.EvaluateAsync(At(Syn(LocalHost, "10.60.70.66", 445), 10))).Matched);

        var r758 = Rule("R758");
        var trigger = Syn("8.8.8.8", LocalHost, 41000); trigger.IsUdp = true;
        Assert.False((await r758.EvaluateAsync(At(trigger, 0))).Matched);
        Assert.False((await r758.EvaluateAsync(At(Syn(LocalHost, "8.8.8.8", 4444), 10))).Matched);

        var vnc = VncSynAck("x11vnc"); vnc.IsUdp = true;
        Assert.False((await Rule("R759").EvaluateAsync(At(vnc, 0))).Matched);

        var http = Http("osascript",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 Chrome/120.0 Safari/537.36");
        http.IsUdp = true;
        Assert.False((await Rule("R760").EvaluateAsync(At(http, 0))).Matched);

        foreach (var id in new[] { "R761", "R762" })
        {
            var rule = Rule(id);
            for (var i = 0; i < 4; i++)
            {
                var x = Tls(id == "R761" ? "anydesk.exe" : "msbuild.exe",
                    id == "R761" ? "relay.anydesk.example" : "packages.example",
                    id == "R761" ? 300 : 1600);
                x.IsUdp = true;
                Assert.False((await rule.EvaluateAsync(At(x, i * 15))).Matched);
            }
        }

        foreach (var id in new[] { "R763", "R764" })
        {
            var rule = Rule(id);
            for (var i = 1; i <= 3; i++)
            {
                var x = Dns(id == "R763" ? "busybox" : "dnscat2",
                    EncodedLabel(i) + (id == "R763" ? ".exfil.example" : ".tunnel.example"));
                x.IsTcp = true;
                Assert.False((await rule.EvaluateAsync(At(x, i))).Matched);
            }
        }

        var r765 = Rule("R765");
        var service = Syn("8.8.8.8", LocalHost, 22); service.IsUdp = true;
        Assert.False((await r765.EvaluateAsync(At(service, 0))).Matched);
        Assert.False((await r765.EvaluateAsync(At(Tls("bash", "callback.example", 300), 20))).Matched);
    }

    [Fact]
    public async Task StatefulRulesRejectReplayReverseTimeAndExpiry()
    {
        var r757 = Rule("R757");
        var firstConflict = NameConflict();
        await r757.EvaluateAsync(At(firstConflict, 0));
        var replayConflict = NameConflict(); replayConflict.Id = firstConflict.Id;
        Assert.False((await r757.EvaluateAsync(At(replayConflict, 1))).Matched);
        Assert.True((await r757.EvaluateAsync(At(Syn(LocalHost, "10.60.70.66", 445), 10))).Matched);

        var r758 = Rule("R758");
        await r758.EvaluateAsync(At(Syn("8.8.8.8", LocalHost, 41000), 30));
        Assert.False((await r758.EvaluateAsync(At(Syn(LocalHost, "8.8.8.8", 4444), 20))).Matched);

        var r761 = Rule("R761");
        await r761.EvaluateAsync(At(Tls("anydesk.exe", "relay.anydesk.example", 300), 60));
        Assert.False((await r761.EvaluateAsync(At(Tls("anydesk.exe", "relay.anydesk.example", 300), 50))).Matched);

        var r763 = Rule("R763");
        var dns = Dns("busybox", EncodedLabel(1) + ".exfil.example");
        await r763.EvaluateAsync(At(dns, 0));
        var duplicate = Dns("busybox", EncodedLabel(2) + ".exfil.example"); duplicate.Id = dns.Id;
        Assert.False((await r763.EvaluateAsync(At(duplicate, 1))).Matched);

        var r765 = Rule("R765");
        await r765.EvaluateAsync(At(Syn("8.8.8.8", LocalHost, 22), 0));
        Assert.False((await r765.EvaluateAsync(At(Tls("bash", "callback.example", 300), 91))).Matched);
    }

    [Theory]
    [InlineData("R756")][InlineData("R757")][InlineData("R758")][InlineData("R759")][InlineData("R760")]
    [InlineData("R761")][InlineData("R762")][InlineData("R763")][InlineData("R764")][InlineData("R765")]
    public async Task EveryRuleOwnsCooldownAndRecovery(string id)
    {
        var rule = Rule(id);
        Assert.True((await Trigger(rule, id, 0)).Matched);

        var repeat = await Trigger(rule, id, 120);
        Assert.True(repeat.Suppressed);
        Assert.Empty(repeat.Events);

        Assert.True((await Trigger(rule, id, 800)).Matched);
    }

    [Fact]
    public async Task NeighboringFamiliesRemainIndependent()
    {
        // R757 is not R083's standalone name-service-conflict detector.
        Assert.False((await Rule("R757").EvaluateAsync(At(NameConflict(), 0))).Matched);

        // R759 is process-attributed and does not absorb transport-only VNC exposure.
        Assert.False((await Rule("R759").EvaluateAsync(At(VncSynAck("sshd"), 0))).Matched);

        // R760 intentionally excludes curl/wget, which belong to R725.
        Assert.False((await Rule("R760").EvaluateAsync(At(Http("curl",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"), 0))).Matched);

        // R763 and R764 use disjoint DNS process families.
        var esxi = Rule("R763");
        for (var i = 1; i <= 3; i++)
            Assert.False((await esxi.EvaluateAsync(At(Dns("dnscat2", EncodedLabel(i) + ".exfil.example"), i))).Matched);

        var linux = Rule("R764");
        for (var i = 1; i <= 3; i++)
            Assert.False((await linux.EvaluateAsync(At(Dns("busybox", EncodedLabel(i) + ".tunnel.example"), i))).Matched);

        // R765 excludes VNC/5900, which is owned by the VNC sequence family.
        var remoteService = Rule("R765");
        await remoteService.EvaluateAsync(At(Syn("8.8.8.8", LocalHost, 5900), 0));
        Assert.False((await remoteService.EvaluateAsync(At(Tls("bash", "callback.example", 300), 20))).Matched);
    }

    [Theory]
    [InlineData("R756")][InlineData("R757")][InlineData("R758")][InlineData("R759")][InlineData("R760")]
    [InlineData("R761")][InlineData("R762")][InlineData("R763")][InlineData("R764")][InlineData("R765")]
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
