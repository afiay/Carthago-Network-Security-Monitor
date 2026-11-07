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

public sealed class R766R775AdvancedAccuracyBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 7, 1, 0, 0, DateTimeKind.Utc);
    private const string Local = "10.70.80.20";

    private static IDetectionRule Rule(string id) => id switch
    {
        "R766" => new R766_OsascriptHighEntropyDnsQueryBurstRule(),
        "R767" => new R767_WindowsScriptHighEntropyDnsQueryBurstRule(),
        "R768" => new R768_OsascriptOutboundFloodShapeRule(),
        "R769" => new R769_LinuxPerlRubyHttpRequestBurstRule(),
        "R770" => new R770_WindowsLolbinWebTrafficBurstRule(),
        "R771" => new R771_PublicSnmpQueryBurstToPrivateHostRule(),
        "R772" => new R772_PrivateOtServicePayloadFloodShapeRule(),
        "R773" => new R773_PrivateSnmpTargetFanoutDiscoveryRule(),
        "R774" => new R774_MacScreensharingdPublicVncSynAckRule(),
        "R775" => new R775_MacSshdPublicSynAckThenUserToolEgressRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static RuleEvaluationContext At(TrafficRecord r, double seconds)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    private static string Encoded(int i) => i switch
    {
        1 => "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
        2 => "b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7",
        _ => "c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
    };

    private static TrafficRecord Dns(string process, string qname)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = Local,
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
            ProcessId = 9100,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord Http(string process)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = Local,
            Destination = "8.8.4.4",
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            IsUdp = false,
            IsQuic = false,
            SourcePort = 52000,
            DestinationPort = 80,
            TcpFlags = 0x18,
            L4Len = 240,
            Length = 280,
            ApplicationProtocol = "HTTP",
            HttpMethod = "GET",
            HttpUri = "/api/check?token=VERY-PRIVATE",
            HttpHost = "api.example",
            HttpRequestHeaders = "Host: api.example\r\n\r\n",
            ProcessName = process,
            ProcessId = 9200,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord Tls(
        string process,
        string source = Local,
        string destination = "8.8.4.4",
        int l4 = 300)
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
            DestinationPort = 443,
            TcpFlags = 0x18,
            L4Len = l4,
            Length = l4 + 40,
            TlsVersion = "TLS1.3",
            Sni = "service.example",
            ProcessName = process,
            ProcessId = 9300,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord FloodUdp(string process)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = Local,
            Destination = "9.9.9.9",
            IpVersion = 4,
            Protocol = "UDP",
            IsTcp = false,
            IsUdp = true,
            IsQuic = false,
            SourcePort = 52002,
            DestinationPort = 9999,
            TcpFlags = null,
            L4Len = 96,
            Length = 124,
            ProcessName = process,
            ProcessId = 9400,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord Snmp(string source, string destination)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = source,
            Destination = destination,
            IpVersion = 4,
            Protocol = "UDP",
            IsTcp = false,
            IsUdp = true,
            IsQuic = false,
            SourcePort = 54000,
            DestinationPort = 161,
            TcpFlags = null,
            L4Len = 84,
            Length = 112,
            ApplicationProtocol = "SNMP",
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord OtUdp(int port = 502)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "10.70.80.30",
            Destination = "10.70.80.60",
            IpVersion = 4,
            Protocol = "UDP",
            IsTcp = false,
            IsUdp = true,
            IsQuic = false,
            SourcePort = 55000,
            DestinationPort = port,
            TcpFlags = null,
            L4Len = 96,
            Length = 124,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord SynAck(
        string process,
        int sourcePort,
        string source = Local,
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
            SourcePort = sourcePort,
            DestinationPort = 55000,
            TcpFlags = 0x12,
            L4Len = null,
            Length = 40,
            ProcessName = process,
            ProcessId = 9500,
            Info = "RAW-SECRET-MARKER"
        };

    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, double start)
    {
        switch (id)
        {
            case "R766":
                await rule.EvaluateAsync(At(Dns("osascript", Encoded(1) + ".mac.example"), start));
                await rule.EvaluateAsync(At(Dns("osascript", Encoded(2) + ".mac.example"), start + 1));
                return await rule.EvaluateAsync(At(Dns("osascript", Encoded(3) + ".mac.example"), start + 2));

            case "R767":
                await rule.EvaluateAsync(At(Dns("powershell.exe", Encoded(1) + ".win.example"), start));
                await rule.EvaluateAsync(At(Dns("powershell.exe", Encoded(2) + ".win.example"), start + 1));
                return await rule.EvaluateAsync(At(Dns("powershell.exe", Encoded(3) + ".win.example"), start + 2));

            case "R768":
                for (var i = 0; i < 11; i++)
                    await rule.EvaluateAsync(At(FloodUdp("osascript"), start + i * 0.8));
                return await rule.EvaluateAsync(At(FloodUdp("osascript"), start + 8.8));

            case "R769":
                for (var i = 0; i < 11; i++)
                    await rule.EvaluateAsync(At(Http("perl"), start + i * 0.8));
                return await rule.EvaluateAsync(At(Http("perl"), start + 8.8));

            case "R770":
                for (var i = 0; i < 7; i++)
                    await rule.EvaluateAsync(At(Tls("mshta.exe"), start + i * 2));
                return await rule.EvaluateAsync(At(Tls("mshta.exe"), start + 14));

            case "R771":
                for (var i = 0; i < 11; i++)
                    await rule.EvaluateAsync(At(Snmp("8.8.8.8", "10.70.80.60"), start + i * 0.8));
                return await rule.EvaluateAsync(At(Snmp("8.8.8.8", "10.70.80.60"), start + 8.8));

            case "R772":
                for (var i = 0; i < 19; i++)
                    await rule.EvaluateAsync(At(OtUdp(), start + i * 0.5));
                return await rule.EvaluateAsync(At(OtUdp(), start + 9.5));

            case "R773":
                await rule.EvaluateAsync(At(Snmp("10.70.80.30", "10.70.80.61"), start));
                await rule.EvaluateAsync(At(Snmp("10.70.80.30", "10.70.80.62"), start + 1));
                await rule.EvaluateAsync(At(Snmp("10.70.80.30", "10.70.80.63"), start + 2));
                return await rule.EvaluateAsync(At(Snmp("10.70.80.30", "10.70.80.64"), start + 3));

            case "R774":
                return await rule.EvaluateAsync(At(SynAck("screensharingd", 5900), start));

            case "R775":
                await rule.EvaluateAsync(At(SynAck("sshd", 22), start));
                return await rule.EvaluateAsync(At(Tls("zsh"), start + 20));

            default:
                throw new ArgumentOutOfRangeException(nameof(id));
        }
    }

    private static async Task<RuleEvaluationResult> NearMiss(IDetectionRule rule, string id)
    {
        switch (id)
        {
            case "R766":
                for (var i = 1; i <= 3; i++)
                    await rule.EvaluateAsync(At(Dns("curl", Encoded(i) + ".mac.example"), i));
                return await rule.EvaluateAsync(At(Dns("curl", Encoded(1) + ".mac.example"), 4));

            case "R767":
                for (var i = 1; i <= 3; i++)
                    await rule.EvaluateAsync(At(Dns("chrome.exe", Encoded(i) + ".win.example"), i));
                return await rule.EvaluateAsync(At(Dns("chrome.exe", Encoded(1) + ".win.example"), 4));

            case "R768":
                for (var i = 0; i < 12; i++)
                    await rule.EvaluateAsync(At(FloodUdp("bash"), i * 0.8));
                return await rule.EvaluateAsync(At(FloodUdp("bash"), 10));

            case "R769":
                for (var i = 0; i < 12; i++)
                    await rule.EvaluateAsync(At(Http("python3"), i * 0.8));
                return await rule.EvaluateAsync(At(Http("python3"), 10));

            case "R770":
                for (var i = 0; i < 8; i++)
                    await rule.EvaluateAsync(At(Tls("powershell.exe"), i * 2));
                return await rule.EvaluateAsync(At(Tls("powershell.exe"), 16));

            case "R771":
                for (var i = 0; i < 12; i++)
                    await rule.EvaluateAsync(At(Snmp("10.70.80.30", "10.70.80.60"), i * 0.8));
                return await rule.EvaluateAsync(At(Snmp("10.70.80.30", "10.70.80.60"), 10));

            case "R772":
                for (var i = 0; i < 20; i++)
                    await rule.EvaluateAsync(At(OtUdp(443), i * 0.5));
                return await rule.EvaluateAsync(At(OtUdp(443), 10));

            case "R773":
                for (var i = 0; i < 4; i++)
                    await rule.EvaluateAsync(At(Snmp("10.70.80.30", "10.70.80.61"), i));
                return await rule.EvaluateAsync(At(Snmp("10.70.80.30", "10.70.80.61"), 5));

            case "R774":
                return await rule.EvaluateAsync(At(SynAck("x11vnc", 5900), 0));

            case "R775":
                await rule.EvaluateAsync(At(SynAck("sshd", 22, "10.70.80.21"), 0));
                return await rule.EvaluateAsync(At(Tls("zsh"), 20));

            default:
                throw new ArgumentOutOfRangeException(nameof(id));
        }
    }

    [Theory]
    [InlineData("R766")][InlineData("R767")][InlineData("R768")][InlineData("R769")][InlineData("R770")]
    [InlineData("R771")][InlineData("R772")][InlineData("R773")][InlineData("R774")][InlineData("R775")]
    public async Task PositiveShapesMatchWithoutLeakingRawEvidence(string id)
    {
        var result = await Trigger(Rule(id), id, 0);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        var json = JsonSerializer.Serialize(evt);
        var lower = json.ToLowerInvariant();
        Assert.Contains("workbook.R", json);
        Assert.DoesNotContain("RAW-SECRET-MARKER", json);
        Assert.DoesNotContain("VERY-PRIVATE", json);
        Assert.DoesNotContain(Encoded(1).ToLowerInvariant(), lower);
        Assert.DoesNotContain(Encoded(2).ToLowerInvariant(), lower);
        Assert.DoesNotContain(Encoded(3).ToLowerInvariant(), lower);
    }

    [Theory]
    [InlineData("R766")][InlineData("R767")][InlineData("R768")][InlineData("R769")][InlineData("R770")]
    [InlineData("R771")][InlineData("R772")][InlineData("R773")][InlineData("R774")][InlineData("R775")]
    public async Task RuleSpecificNearMissDoesNotMatch(string id)
        => Assert.False((await NearMiss(Rule(id), id)).Matched);

    [Fact]
    public async Task ProcessGatedRulesRequireLocalAttribution()
    {
        foreach (var id in new[] { "R766", "R767", "R768", "R769", "R770", "R774" })
        {
            var rule = Rule(id);
            TrafficRecord r = id switch
            {
                "R766" => Dns("osascript", Encoded(1) + ".mac.example"),
                "R767" => Dns("powershell.exe", Encoded(1) + ".win.example"),
                "R768" => FloodUdp("osascript"),
                "R769" => Http("perl"),
                "R770" => Tls("mshta.exe"),
                "R774" => SynAck("screensharingd", 5900),
                _ => throw new ArgumentOutOfRangeException()
            };
            r.ProcessId = 0;
            Assert.False((await rule.EvaluateAsync(At(r, 0))).Matched);
        }

        var r775 = Rule("R775");
        await r775.EvaluateAsync(At(SynAck("sshd", 22), 0));
        var follow = Tls("zsh");
        follow.ProcessId = 0;
        Assert.False((await r775.EvaluateAsync(At(follow, 20))).Matched);
    }

    [Fact]
    public async Task ContradictoryTransportFailsClosed()
    {
        foreach (var id in new[] { "R766", "R767" })
        {
            var rule = Rule(id);
            for (var i = 1; i <= 3; i++)
            {
                var d = Dns(id == "R766" ? "osascript" : "powershell.exe",
                    Encoded(i) + (id == "R766" ? ".mac.example" : ".win.example"));
                d.IsTcp = true;
                Assert.False((await rule.EvaluateAsync(At(d, i))).Matched);
            }
        }

        var flood = FloodUdp("osascript"); flood.IsTcp = true;
        Assert.False((await Rule("R768").EvaluateAsync(At(flood, 0))).Matched);

        var http = Http("perl"); http.IsUdp = true;
        Assert.False((await Rule("R769").EvaluateAsync(At(http, 0))).Matched);

        var tls = Tls("mshta.exe"); tls.IsUdp = true;
        Assert.False((await Rule("R770").EvaluateAsync(At(tls, 0))).Matched);

        var snmp = Snmp("8.8.8.8", "10.70.80.60"); snmp.IsTcp = true;
        Assert.False((await Rule("R771").EvaluateAsync(At(snmp, 0))).Matched);

        var ot = OtUdp(); ot.IsTcp = true;
        Assert.False((await Rule("R772").EvaluateAsync(At(ot, 0))).Matched);

        var snmpPrivate = Snmp("10.70.80.30", "10.70.80.61"); snmpPrivate.IsTcp = true;
        Assert.False((await Rule("R773").EvaluateAsync(At(snmpPrivate, 0))).Matched);

        var vnc = SynAck("screensharingd", 5900); vnc.IsUdp = true;
        Assert.False((await Rule("R774").EvaluateAsync(At(vnc, 0))).Matched);

        var ssh = SynAck("sshd", 22); ssh.IsUdp = true;
        var r775 = Rule("R775");
        Assert.False((await r775.EvaluateAsync(At(ssh, 0))).Matched);
        Assert.False((await r775.EvaluateAsync(At(Tls("zsh"), 20))).Matched);
    }

    [Fact]
    public async Task StatefulCandidatesRejectReplayReverseTimeAndExpiry()
    {
        var r766 = Rule("R766");
        var first = Dns("osascript", Encoded(1) + ".mac.example");
        await r766.EvaluateAsync(At(first, 0));
        var duplicate = Dns("osascript", Encoded(2) + ".mac.example"); duplicate.Id = first.Id;
        Assert.False((await r766.EvaluateAsync(At(duplicate, 1))).Matched);

        var r768 = Rule("R768");
        await r768.EvaluateAsync(At(FloodUdp("osascript"), 30));
        Assert.False((await r768.EvaluateAsync(At(FloodUdp("osascript"), 20))).Matched);

        var r769 = Rule("R769");
        for (var i = 0; i < 11; i++)
            await r769.EvaluateAsync(At(Http("perl"), i * 0.8));
        Assert.False((await r769.EvaluateAsync(At(Http("perl"), 11))).Matched);

        var r773 = Rule("R773");
        await r773.EvaluateAsync(At(Snmp("10.70.80.30", "10.70.80.61"), 0));
        await r773.EvaluateAsync(At(Snmp("10.70.80.30", "10.70.80.61"), 1));
        await r773.EvaluateAsync(At(Snmp("10.70.80.30", "10.70.80.62"), 2));
        Assert.False((await r773.EvaluateAsync(At(Snmp("10.70.80.30", "10.70.80.63"), 3))).Matched);

        var r775 = Rule("R775");
        await r775.EvaluateAsync(At(SynAck("sshd", 22), 0));
        Assert.False((await r775.EvaluateAsync(At(Tls("zsh"), 91))).Matched);
    }

    [Theory]
    [InlineData("R766")][InlineData("R767")][InlineData("R768")][InlineData("R769")][InlineData("R770")]
    [InlineData("R771")][InlineData("R772")][InlineData("R773")][InlineData("R774")][InlineData("R775")]
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
        var macDns = Rule("R766");
        for (var i = 1; i <= 3; i++)
            Assert.False((await macDns.EvaluateAsync(At(Dns("powershell.exe", Encoded(i) + ".mac.example"), i))).Matched);

        var winDns = Rule("R767");
        for (var i = 1; i <= 3; i++)
            Assert.False((await winDns.EvaluateAsync(At(Dns("osascript", Encoded(i) + ".win.example"), i))).Matched);

        var perlRuby = Rule("R769");
        for (var i = 0; i < 12; i++)
            Assert.False((await perlRuby.EvaluateAsync(At(Http("python3"), i * 0.8))).Matched);

        var lolbin = Rule("R770");
        for (var i = 0; i < 8; i++)
            Assert.False((await lolbin.EvaluateAsync(At(Tls("powershell.exe"), i * 2))).Matched);

        var publicSnmp = Rule("R771");
        for (var i = 0; i < 12; i++)
            Assert.False((await publicSnmp.EvaluateAsync(At(Snmp("10.70.80.30", "10.70.80.60"), i * 0.8))).Matched);

        var internalSnmp = Rule("R773");
        for (var i = 0; i < 4; i++)
            Assert.False((await internalSnmp.EvaluateAsync(At(Snmp("8.8.8.8", "10.70.80." + (61 + i)), i))).Matched);

        Assert.False((await Rule("R774").EvaluateAsync(At(SynAck("x11vnc", 5900), 0))).Matched);

        var macSsh = Rule("R775");
        await macSsh.EvaluateAsync(At(SynAck("sshd", 22), 0));
        Assert.False((await macSsh.EvaluateAsync(At(Tls("bash"), 20))).Matched);
    }

    [Theory]
    [InlineData("R766")][InlineData("R767")][InlineData("R768")][InlineData("R769")][InlineData("R770")]
    [InlineData("R771")][InlineData("R772")][InlineData("R773")][InlineData("R774")][InlineData("R775")]
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
