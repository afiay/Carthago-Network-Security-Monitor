// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored before production; no tests or builds executed.
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

public sealed class R846R855ObservableCandidateBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 10, 0, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids =
        { "R846", "R847", "R848", "R849", "R850", "R851", "R852", "R853", "R854", "R855" };

    private static IDetectionRule Rule(string id) => id switch
    {
        "R846" => new R846_DialerExternalSynRule(),
        "R847" => new R847_AddinUtilExternalSynRule(),
        "R848" => new R848_Eqnedt32ExternalSynRule(),
        "R849" => new R849_PythonUniformOutboundPayloadCadenceRule(),
        "R850" => new R850_PublicOpenSlpThenInternalSshSynRule(),
        "R851" => new R851_PublicSshIngressThenShellPublicSynRule(),
        "R852" => new R852_PowershellCloudTlsPayloadBurstRule(),
        "R853" => new R853_ReportingPeerSourceMacChangeRule(),
        "R854" => new R854_PowershellAlternateNetworkTypeSynRule(),
        "R855" => new R855_HostdExternalHttpPostBurstRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static int Threshold(string id) => id switch
    {
        "R846" or "R847" or "R848" => 1,
        "R849" => 4,
        "R852" or "R855" => 5,
        _ => 2
    };

    private static TrafficRecord Packet(string id, int stage)
    {
        var r = new TrafficRecord
        {
            Id = Guid.NewGuid(), IpVersion = 4, Source = "10.1.1.10", Destination = "8.8.8.8",
            Protocol = "TCP", IsTcp = true, SourcePort = 51000, DestinationPort = 8443,
            TcpFlags = 0x02, L4Len = 0, Length = 40, ProcessName = "dialer.exe", ProcessId = 246,
            Info = "PRIVATE-RAW-EVIDENCE-MARKER"
        };
        switch (id)
        {
            case "R846":
                r.ProcessName = "dialer.exe"; r.DestinationPort = 443;
                break;
            case "R847":
                r.ProcessName = "addinutil.exe";
                break;
            case "R848":
                r.ProcessName = "eqnedt32.exe"; r.DestinationPort = 80;
                break;
            case "R849":
                r.ProcessName = "python3"; Data(r, 1024 + (stage % 2) * 12);
                r.DestinationPort = 4444;
                break;
            case "R850":
                if (stage == 0)
                {
                    Syn(r, "8.8.8.8", "10.1.1.10", 54000, 427);
                    r.ProcessName = null; r.ProcessId = 0;
                }
                else
                {
                    Syn(r, "10.1.1.10", "10.2.2.20", 51000, 22);
                    r.ProcessName = "ssh"; r.ProcessId = 246;
                }
                break;
            case "R851":
                if (stage == 0)
                {
                    Syn(r, "8.8.8.8", "10.1.1.10", 54000, 22);
                    r.ProcessName = null; r.ProcessId = 0;
                }
                else
                {
                    r.ProcessName = "bash"; r.DestinationPort = 8443;
                }
                break;
            case "R852":
                r.ProcessName = "powershell.exe"; Data(r, 2050);
                r.DestinationPort = 443; r.TlsVersion = "TLS1.3"; r.Sni = "content.dropboxapi.com";
                break;
            case "R853":
                r.ProcessName = null; r.ProcessId = 0; Data(r, 480);
                r.Destination = "10.1.1.20"; r.DestinationPort = 1883;
                r.MacSource = stage == 0 ? "02:11:22:33:44:55" : "02:11:22:33:44:66";
                break;
            case "R854":
                r.ProcessName = "powershell.exe";
                r.NetworkType = stage == 0 ? "Wi-Fi" : "Cellular";
                break;
            case "R855":
                r.ProcessName = "hostd"; r.DestinationPort = 8080;
                HttpPost(r, "/api/upload");
                break;
        }
        return r;
    }

    private static void Syn(TrafficRecord r, string src, string dest, int srcPort, int destPort)
    {
        r.Source = src; r.Destination = dest; r.SourcePort = srcPort; r.DestinationPort = destPort;
        r.TcpFlags = 0x02; r.L4Len = 0; r.Length = 40;
        r.TlsVersion = r.Sni = r.HttpMethod = r.HttpUri = r.ApplicationProtocol = null;
    }

    private static void Data(TrafficRecord r, int size)
    {
        r.TcpFlags = 0x18; r.L4Len = size; r.Length = size + 40;
    }

    private static void HttpPost(TrafficRecord r, string uri)
    {
        Data(r, 1200); r.ApplicationProtocol = "HTTP"; r.HttpMethod = "POST";
        r.HttpUri = uri; r.HttpHost = "relay.example.net";
    }

    private static RuleEvaluationContext At(TrafficRecord r, double seconds)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, double start)
    {
        RuleEvaluationResult? result = null;
        for (var i = 0; i < Threshold(id); i++)
            result = await rule.EvaluateAsync(At(Packet(id, i), start + 3 * i));
        return result!;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task NarrowPositiveMatchesAndRawPacketInfoIsExcluded(string id)
    {
        var result = await Trigger(Rule(id), id, 0);
        Assert.True(result.Matched);
        Assert.DoesNotContain("PRIVATE-RAW-EVIDENCE-MARKER", JsonSerializer.Serialize(result.Events));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task ContradictoryTcpUdpFlagsAndMissingPeerFailClosed(string id)
    {
        var contradictory = Rule(id);
        var missing = Rule(id);
        for (var i = 0; i < Threshold(id); i++)
        {
            var dual = Packet(id, i); dual.IsUdp = true;
            Assert.False((await contradictory.EvaluateAsync(At(dual, i * 3))).Matched);
            var noPeer = Packet(id, i); noPeer.Destination = null;
            Assert.False((await missing.EvaluateAsync(At(noPeer, i * 3))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task BenignNearMissCannotTrigger(string id)
    {
        var rule = Rule(id);
        for (var i = 0; i < Threshold(id) + 2; i++)
        {
            var r = Packet(id, i % Threshold(id));
            switch (id)
            {
                case "R846":
                case "R847":
                case "R848":
                case "R849": r.ProcessName = "explorer.exe"; break;
                case "R850": r.DestinationPort = 80; break;
                case "R851": r.DestinationPort = 80; r.ProcessName = "explorer.exe"; break;
                case "R852": r.Sni = "updates.example.net"; break;
                case "R853": r.MacSource = "02:11:22:33:44:55"; break;
                case "R854": r.NetworkType = "Ethernet"; break;
                case "R855": r.HttpMethod = "GET"; break;
            }
            Assert.False((await rule.EvaluateAsync(At(r, i * 3))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task DuplicateAndExpiredFirstObservationFail(string id)
    {
        var rule = Rule(id); var first = Packet(id, 0);
        await rule.EvaluateAsync(At(first, 10));
        for (var i = 1; i < Threshold(id); i++)
        {
            var sameId = Packet(id, i); sameId.Id = first.Id;
            Assert.False((await rule.EvaluateAsync(At(sameId, 10 + 3 * i))).Matched);
        }
        if (Threshold(id) == 1) return;
        var expired = Rule(id);
        await expired.EvaluateAsync(At(Packet(id, 0), 0));
        for (var i = 1; i < Threshold(id); i++)
            Assert.False((await expired.EvaluateAsync(At(Packet(id, i), 250 + 3 * i))).Matched);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task CooldownSuppressesThenRecovers(string id)
    {
        var rule = Rule(id);
        Assert.True((await Trigger(rule, id, 0)).Matched);
        Assert.True((await Trigger(rule, id, 300)).Suppressed);
        Assert.True((await Trigger(rule, id, 950)).Matched);
    }

    [Fact]
    public async Task UniformChunkCadenceRejectsIrregularSizesAndTimes()
    {
        var rule = Rule("R849");
        await rule.EvaluateAsync(At(Packet("R849", 0), 0));
        var large = Packet("R849", 1); large.L4Len = 3000; large.Length = 3040;
        Assert.False((await rule.EvaluateAsync(At(large, 3))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Packet("R849", 2), 4))).Matched);
    }

    [Fact]
    public async Task MacChangeRequiresASecondCanonicalMacFromSameReportingPeer()
    {
        var rule = Rule("R853");
        await rule.EvaluateAsync(At(Packet("R853", 0), 0));
        var malformed = Packet("R853", 1); malformed.MacSource = "NOT-A-MAC";
        Assert.False((await rule.EvaluateAsync(At(malformed, 3))).Matched);
        var otherPeer = Packet("R853", 1); otherPeer.Destination = "10.1.1.30";
        Assert.False((await rule.EvaluateAsync(At(otherPeer, 6))).Matched);
    }

    [Fact]
    public async Task TheTwoRareWindowsProcessRulesCannotConsumeDialerPacket()
    {
        var dialer = Packet("R846", 0);
        Assert.False((await Rule("R847").EvaluateAsync(At(dialer, 0))).Matched);
        Assert.False((await Rule("R848").EvaluateAsync(At(dialer, 0))).Matched);
    }

    [Fact]
    public async Task NeighboringRulesDoNotShareDetectorState()
    {
        for (var i = 0; i < Ids.Length; i++)
        {
            var rule = Rule(Ids[i]); var otherId = Ids[(i + 1) % Ids.Length];
            for (var j = 0; j < Threshold(otherId) + 2; j++)
                Assert.False((await rule.EvaluateAsync(At(Packet(otherId, j % Threshold(otherId)), j * 3))).Matched);
        }
    }

    [Fact]
    public void RegistryContainsOneIndependentCandidateShadowRulePerId()
    {
        var rules = RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count, rules.Select(r => r.Descriptor.RuleId)
            .Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var id in Ids)
        {
            var rule = Assert.Single(rules.Where(r => r.Descriptor.RuleId == id));
            var p = Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(rule).PrecisionProfile;
            Assert.Equal(RulePrecisionMaturity.Candidate, p.Maturity);
            Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
        }
    }

    public static TheoryData<string> Cases => new()
    { "R846", "R847", "R848", "R849", "R850", "R851", "R852", "R853", "R854", "R855" };
}
