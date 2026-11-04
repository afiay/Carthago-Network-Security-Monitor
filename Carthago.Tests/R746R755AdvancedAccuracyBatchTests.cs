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

public sealed class R746R755AdvancedAccuracyBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 4, 16, 0, 0, DateTimeKind.Utc);
    private const string LocalHost = "10.40.50.20";

    private static IDetectionRule Rule(string id) => id switch
    {
        "R746" => new R746_EsxiManagementProcessNonstandardTlsBurstRule(),
        "R747" => new R747_WindowsArchiveToolExternalTlsBurstRule(),
        "R748" => new R748_LinuxCryptoToolUncommonPortPayloadBurstRule(),
        "R749" => new R749_EsxiShellToolExternalFtpUploadRequestRule(),
        "R750" => new R750_MacProcessCloudStorageTlsPayloadBurstRule(),
        "R751" => new R751_MacProcessCodeRepositoryTlsPayloadBurstRule(),
        "R752" => new R752_MsiexecRemoteMsiHttpGetRule(),
        "R753" => new R753_OsascriptExternalTlsRecurrentCadenceRule(),
        "R754" => new R754_MacTransferToolPrivatePeerPayloadBurstRule(),
        "R755" => new R755_PublicVncAttemptThenMacScriptEgressRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static RuleEvaluationContext At(TrafficRecord r, double seconds)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    private static TrafficRecord Tls(
        string process,
        string sni,
        int port = 443,
        int l4 = 1600,
        int pid = 7100,
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

    private static TrafficRecord Raw(
        string process,
        string destination = "8.8.4.4",
        int port = 5555,
        int l4 = 1400,
        int pid = 7200,
        string source = LocalHost)
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
            SourcePort = 52001,
            DestinationPort = port,
            TcpFlags = 0x18,
            L4Len = l4,
            Length = l4 + 40,
            ProcessName = process,
            ProcessId = pid,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord Ftp(string process, string operation = "ftp.stor")
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
            SourcePort = 52002,
            DestinationPort = 21,
            TcpFlags = 0x18,
            L4Len = 180,
            Length = 220,
            ApplicationProtocol = operation,
            ProcessName = process,
            ProcessId = 7300,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord Http(
        string process,
        string method,
        string uri,
        string host = "packages.example")
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
            SourcePort = 52003,
            DestinationPort = 80,
            TcpFlags = 0x18,
            L4Len = 320,
            Length = 360,
            ApplicationProtocol = "HTTP",
            HttpMethod = method,
            HttpUri = uri,
            HttpHost = host,
            HttpRequestHeaders = "Host: " + host + "\r\n",
            ProcessName = process,
            ProcessId = 7400,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord VncIngress(string privateHost = LocalHost)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "8.8.8.8",
            Destination = privateHost,
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            IsUdp = false,
            IsQuic = false,
            SourcePort = 55000,
            DestinationPort = 5900,
            TcpFlags = 0x02,
            L4Len = null,
            Length = 40,
            Info = "RAW-SECRET-MARKER"
        };

    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, double start)
    {
        switch (id)
        {
            case "R746":
                for (var i = 0; i < 3; i++)
                    await rule.EvaluateAsync(At(Tls("hostd", "gateway.vendor.example", 9443), start + i));
                return await rule.EvaluateAsync(At(Tls("hostd", "gateway.vendor.example", 9443), start + 3));

            case "R747":
                for (var i = 0; i < 3; i++)
                    await rule.EvaluateAsync(At(Tls("winrar.exe", "transfer.example"), start + i));
                return await rule.EvaluateAsync(At(Tls("winrar.exe", "transfer.example"), start + 3));

            case "R748":
                for (var i = 0; i < 3; i++)
                    await rule.EvaluateAsync(At(Raw("openssl"), start + i));
                return await rule.EvaluateAsync(At(Raw("openssl"), start + 3));

            case "R749":
                return await rule.EvaluateAsync(At(Ftp("busybox"), start));

            case "R750":
                for (var i = 0; i < 3; i++)
                    await rule.EvaluateAsync(At(Tls("osascript", "dropbox.com"), start + i));
                return await rule.EvaluateAsync(At(Tls("osascript", "dropbox.com"), start + 3));

            case "R751":
                for (var i = 0; i < 3; i++)
                    await rule.EvaluateAsync(At(Tls("git", "github.com"), start + i));
                return await rule.EvaluateAsync(At(Tls("git", "github.com"), start + 3));

            case "R752":
                return await rule.EvaluateAsync(At(Http("msiexec.exe", "GET",
                    "/packages/agent.msi?token=VERY-PRIVATE"), start));

            case "R753":
                await rule.EvaluateAsync(At(Tls("osascript", "api.vendor.example", l4: 300), start));
                await rule.EvaluateAsync(At(Tls("osascript", "api.vendor.example", l4: 320), start + 45));
                return await rule.EvaluateAsync(At(Tls("osascript", "api.vendor.example", l4: 310), start + 90));

            case "R754":
                for (var i = 0; i < 3; i++)
                    await rule.EvaluateAsync(At(Raw("rsync", "10.40.50.60", 873, 1600), start + i));
                return await rule.EvaluateAsync(At(Raw("rsync", "10.40.50.60", 873, 1600), start + 3));

            case "R755":
                await rule.EvaluateAsync(At(VncIngress(), start));
                return await rule.EvaluateAsync(At(Tls("osascript", "api.vendor.example", l4: 320), start + 20));

            default:
                throw new ArgumentOutOfRangeException(nameof(id));
        }
    }

    private static async Task<RuleEvaluationResult> NearMiss(IDetectionRule rule, string id)
    {
        switch (id)
        {
            case "R746":
                for (var i = 0; i < 4; i++)
                    await rule.EvaluateAsync(At(Tls("hostd", "gateway.vendor.example", 443), i));
                return await rule.EvaluateAsync(At(Tls("hostd", "gateway.vendor.example", 443), 4));

            case "R747":
                for (var i = 0; i < 4; i++)
                    await rule.EvaluateAsync(At(Tls("chrome.exe", "transfer.example"), i));
                return await rule.EvaluateAsync(At(Tls("chrome.exe", "transfer.example"), 4));

            case "R748":
                for (var i = 0; i < 4; i++)
                    await rule.EvaluateAsync(At(Raw("openssl", port: 443), i));
                return await rule.EvaluateAsync(At(Raw("openssl", port: 443), 4));

            case "R749":
                return await rule.EvaluateAsync(At(Ftp("busybox", "ftp.list"), 0));

            case "R750":
                for (var i = 0; i < 4; i++)
                    await rule.EvaluateAsync(At(Tls("osascript", "api.vendor.example"), i));
                return await rule.EvaluateAsync(At(Tls("osascript", "api.vendor.example"), 4));

            case "R751":
                for (var i = 0; i < 4; i++)
                    await rule.EvaluateAsync(At(Tls("git", "dropbox.com"), i));
                return await rule.EvaluateAsync(At(Tls("git", "dropbox.com"), 4));

            case "R752":
                return await rule.EvaluateAsync(At(Http("msiexec.exe", "GET", "/packages/agent.exe"), 0));

            case "R753":
                await rule.EvaluateAsync(At(Tls("osascript", "api.vendor.example", l4: 300), 0));
                await rule.EvaluateAsync(At(Tls("osascript", "api.vendor.example", l4: 620), 45));
                return await rule.EvaluateAsync(At(Tls("osascript", "api.vendor.example", l4: 300), 90));

            case "R754":
                for (var i = 0; i < 4; i++)
                    await rule.EvaluateAsync(At(Raw("rsync", "8.8.8.8", 873, 1600), i));
                return await rule.EvaluateAsync(At(Raw("rsync", "8.8.8.8", 873, 1600), 4));

            case "R755":
                await rule.EvaluateAsync(At(VncIngress("10.40.50.21"), 0));
                return await rule.EvaluateAsync(At(Tls("osascript", "api.vendor.example", l4: 320), 20));

            default:
                throw new ArgumentOutOfRangeException(nameof(id));
        }
    }

    private static TrafficRecord Representative(string id) => id switch
    {
        "R746" => Tls("hostd", "gateway.vendor.example", 9443),
        "R747" => Tls("winrar.exe", "transfer.example"),
        "R748" => Raw("openssl"),
        "R749" => Ftp("busybox"),
        "R750" => Tls("osascript", "dropbox.com"),
        "R751" => Tls("git", "github.com"),
        "R752" => Http("msiexec.exe", "GET", "/packages/agent.msi?token=VERY-PRIVATE"),
        "R753" => Tls("osascript", "api.vendor.example", l4: 300),
        "R754" => Raw("rsync", "10.40.50.60", 873, 1600),
        "R755" => Tls("osascript", "api.vendor.example", l4: 320),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    [Theory]
    [InlineData("R746")][InlineData("R747")][InlineData("R748")][InlineData("R749")][InlineData("R750")]
    [InlineData("R751")][InlineData("R752")][InlineData("R753")][InlineData("R754")][InlineData("R755")]
    public async Task PositiveShapesMatchAndFixedEvidenceDoesNotLeakRawInfo(string id)
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
    [InlineData("R746")][InlineData("R747")][InlineData("R748")][InlineData("R749")][InlineData("R750")]
    [InlineData("R751")][InlineData("R752")][InlineData("R753")][InlineData("R754")][InlineData("R755")]
    public async Task RuleSpecificBenignNearMissDoesNotMatch(string id)
        => Assert.False((await NearMiss(Rule(id), id)).Matched);

    [Theory]
    [InlineData("R746")][InlineData("R747")][InlineData("R748")][InlineData("R749")][InlineData("R750")]
    [InlineData("R751")][InlineData("R752")][InlineData("R753")][InlineData("R754")]
    public async Task MissingProcessAttributionAndContradictoryTransportFailClosed(string id)
    {
        var missing = Representative(id);
        missing.ProcessId = 0;
        Assert.False((await Rule(id).EvaluateAsync(At(missing, 0))).Matched);

        var contradictory = Representative(id);
        contradictory.IsUdp = true;
        Assert.False((await Rule(id).EvaluateAsync(At(contradictory, 0))).Matched);
    }

    [Fact]
    public async Task VncCorrelationRequiresValidIngressAndFollowOnProcessTelemetry()
    {
        var noProcess = Rule("R755");
        await noProcess.EvaluateAsync(At(VncIngress(), 0));
        var follow = Tls("osascript", "api.vendor.example", l4: 320);
        follow.ProcessId = 0;
        Assert.False((await noProcess.EvaluateAsync(At(follow, 20))).Matched);

        var udpIngress = VncIngress();
        udpIngress.IsUdp = true;
        var contradictory = Rule("R755");
        Assert.False((await contradictory.EvaluateAsync(At(udpIngress, 0))).Matched);
        Assert.False((await contradictory.EvaluateAsync(At(
            Tls("osascript", "api.vendor.example", l4: 320), 20))).Matched);
    }

    [Fact]
    public async Task StatefulCandidatesRejectDuplicateReverseTimeAndExpiry()
    {
        var r746 = Rule("R746");
        var first = Tls("hostd", "gateway.vendor.example", 9443);
        await r746.EvaluateAsync(At(first, 0));
        var duplicate = Tls("hostd", "gateway.vendor.example", 9443);
        duplicate.Id = first.Id;
        Assert.False((await r746.EvaluateAsync(At(duplicate, 1))).Matched);

        var r753 = Rule("R753");
        await r753.EvaluateAsync(At(Tls("osascript", "api.vendor.example", l4: 300), 60));
        Assert.False((await r753.EvaluateAsync(At(
            Tls("osascript", "api.vendor.example", l4: 300), 50))).Matched);

        var r754 = Rule("R754");
        await r754.EvaluateAsync(At(Raw("rsync", "10.40.50.60", 873, 1600), 0));
        await r754.EvaluateAsync(At(Raw("rsync", "10.40.50.60", 873, 1600), 1));
        await r754.EvaluateAsync(At(Raw("rsync", "10.40.50.60", 873, 1600), 2));
        Assert.False((await r754.EvaluateAsync(At(
            Raw("rsync", "10.40.50.60", 873, 1600), 121))).Matched);

        var r755 = Rule("R755");
        await r755.EvaluateAsync(At(VncIngress(), 0));
        Assert.False((await r755.EvaluateAsync(At(
            Tls("osascript", "api.vendor.example", l4: 320), 91))).Matched);
    }

    [Theory]
    [InlineData("R746")][InlineData("R747")][InlineData("R748")][InlineData("R749")][InlineData("R750")]
    [InlineData("R751")][InlineData("R752")][InlineData("R753")][InlineData("R754")][InlineData("R755")]
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
    public async Task NeighboringFamiliesDoNotConverge()
    {
        // R749 is not the Windows script-host FTP predicate used by R652.
        Assert.False((await Rule("R749").EvaluateAsync(At(Ftp("wscript.exe"), 0))).Matched);

        // Cloud-storage and code-repository TLS rules remain host-family specific.
        var cloud = Rule("R750");
        for (var i = 0; i < 4; i++)
            Assert.False((await cloud.EvaluateAsync(At(Tls("osascript", "github.com"), i))).Matched);

        var repo = Rule("R751");
        for (var i = 0; i < 4; i++)
            Assert.False((await repo.EvaluateAsync(At(Tls("git", "dropbox.com"), i))).Matched);

        // R753 is deliberately low-volume cadence and does not become R734-style large burst behavior.
        var cadence = Rule("R753");
        await cadence.EvaluateAsync(At(Tls("osascript", "api.vendor.example", l4: 1600), 0));
        await cadence.EvaluateAsync(At(Tls("osascript", "api.vendor.example", l4: 1600), 45));
        Assert.False((await cadence.EvaluateAsync(At(
            Tls("osascript", "api.vendor.example", l4: 1600), 90))).Matched);

        // R754 is private-peer only and therefore separate from external SSH/SCP egress.
        var lateral = Rule("R754");
        for (var i = 0; i < 4; i++)
            Assert.False((await lateral.EvaluateAsync(At(
                Raw("scp", "8.8.8.8", 22, 1600), i))).Matched);
    }

    [Theory]
    [InlineData("R746")][InlineData("R747")][InlineData("R748")][InlineData("R749")][InlineData("R750")]
    [InlineData("R751")][InlineData("R752")][InlineData("R753")][InlineData("R754")][InlineData("R755")]
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
