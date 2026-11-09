// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; authored xUnit source, 0 tests executed.
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

public sealed class R796R805ObservableNetworkBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 9, 0, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids = { "R796", "R797", "R798", "R799", "R800", "R801", "R802", "R803", "R804", "R805" };

    private static IDetectionRule Rule(string id) => id switch
    {
        "R796" => new R796_FrpcInternalThenExternalSynRule(),
        "R797" => new R797_WmicRpcPrivateTargetFanoutRule(),
        "R798" => new R798_DnsThenRecurringTlsSniRule(),
        "R799" => new R799_DnsTxtThenSameHostHttpPostRule(),
        "R800" => new R800_ScadaDeviceSynThenPublicHttpRule(),
        "R801" => new R801_CipIdentityThenModbusSynRule(),
        "R802" => new R802_PythonOtServiceMultiPortProbeRule(),
        "R803" => new R803_CoapDiscoveryThenPublicDnsTxtRule(),
        "R804" => new R804_SnmpProbeThenSshSynRule(),
        "R805" => new R805_EncodedDnsTxtDistinctQueryBurstRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static int Threshold(string id) => id switch
    {
        "R797" or "R798" => 4,
        "R802" => 3,
        "R805" => 5,
        _ => 2
    };
    private static int Spacing(string id) => id == "R798" ? 20 : 3;

    private static TrafficRecord Packet(string id, int stage)
    {
        var r = new TrafficRecord
        {
            Id = Guid.NewGuid(), IpVersion = 4, Source = "10.1.1.10", Destination = "8.8.8.8",
            Protocol = "TCP", IsTcp = true, IsUdp = false,
            SourcePort = 51000, DestinationPort = 443, TcpFlags = 0x02,
            L4Len = 0, Length = 40,
            ProcessName = "powershell.exe", ProcessId = 880,
            Info = "PRIVATE-RAW-EVIDENCE-MARKER"
        };
        switch (id)
        {
            case "R796":
                r.ProcessName = "frpc.exe";
                if (stage == 0) { r.Destination = "10.1.2.20"; r.DestinationPort = 1080; }
                break;
            case "R797":
                r.ProcessName = "wmic.exe"; r.Destination = "10.1.2." + (20 + stage);
                r.DestinationPort = 135;
                break;
            case "R798":
                if (stage == 0)
                {
                    Udp(r, 53, 100);
                    r.ApplicationProtocol = "DNS"; r.DnsQname = "sync.example.org"; r.DnsQtype = "A";
                }
                else
                {
                    r.TcpFlags = 0x18; r.L4Len = 240; r.Length = 280;
                    r.TlsVersion = "TLS1.2"; r.Sni = "sync.example.org";
                }
                break;
            case "R799":
                r.ProcessName = "curl.exe";
                if (stage == 0)
                {
                    Udp(r, 53, 120);
                    r.ApplicationProtocol = "DNS"; r.DnsQname = "telemetry.example.org"; r.DnsQtype = "TXT";
                }
                else
                {
                    r.DestinationPort = 80; r.TcpFlags = 0x18; r.L4Len = 350; r.Length = 390;
                    r.ApplicationProtocol = "HTTP"; r.HttpMethod = "POST";
                    r.HttpUri = "/api/collect"; r.HttpHost = "telemetry.example.org";
                }
                break;
            case "R800":
                r.ProcessName = "scada.exe";
                if (stage == 0) { r.Destination = "10.1.2.20"; r.DestinationPort = 502; }
                else
                {
                    r.DestinationPort = 80; r.TcpFlags = 0x18; r.L4Len = 350; r.Length = 390;
                    r.ApplicationProtocol = "HTTP"; r.HttpMethod = "GET";
                    r.HttpUri = "/api/update"; r.HttpHost = "updates.example.org";
                }
                break;
            case "R801":
                r.ProcessName = "python.exe"; r.Destination = "10.1.2.20";
                if (stage == 0)
                {
                    Udp(r, 44818, 24); r.ApplicationProtocol = "ethernetip.listidentity";
                }
                else { r.DestinationPort = 502; }
                break;
            case "R802":
                r.ProcessName = "python.exe"; r.Destination = "10.1.2.20";
                r.DestinationPort = stage switch { 0 => 102, 1 => 502, _ => 2404 };
                break;
            case "R803":
                r.ProcessName = "iot-agent";
                if (stage == 0)
                {
                    r.Destination = "224.0.1.187"; Udp(r, 5683, 100);
                    r.ApplicationProtocol = "coap.discovery";
                }
                else
                {
                    r.Destination = "9.9.9.9"; Udp(r, 53, 130);
                    r.ApplicationProtocol = "DNS"; r.DnsQname = "signals.example.org"; r.DnsQtype = "TXT";
                }
                break;
            case "R804":
                r.Destination = "10.1.2.20";
                if (stage == 0) Udp(r, 161, 100);
                else r.DestinationPort = 22;
                break;
            case "R805":
                Udp(r, 53, 130); r.ApplicationProtocol = "DNS"; r.DnsQtype = "TXT";
                r.DnsQname = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFG" + "ABCDE"[stage] + ".telemetry.example.org";
                break;
        }
        return r;
    }

    private static void Udp(TrafficRecord r, int port, int length)
    {
        r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP";
        r.TcpFlags = null; r.DestinationPort = port;
        r.L4Len = length; r.Length = length + 28;
    }
    private static RuleEvaluationContext At(TrafficRecord packet, double seconds)
        => new(packet, Sensitivity.Balanced, Epoch.AddSeconds(seconds));
    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, double offset)
    {
        RuleEvaluationResult? last = null;
        for (var i = 0; i < Threshold(id); i++)
            last = await rule.EvaluateAsync(At(Packet(id, i), offset + i * Spacing(id)));
        return last!;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task PositiveAndContradictoryOrMissingEvidence(string id)
    {
        Assert.True((await Trigger(Rule(id), id, 0)).Matched);
        var wrongTransport = Rule(id);
        var missing = Rule(id);
        for (var i = 0; i < Threshold(id); i++)
        {
            var a = Packet(id, i); a.IsTcp = true; a.IsUdp = true;
            Assert.False((await wrongTransport.EvaluateAsync(At(a, i * Spacing(id)))).Matched);
            var b = Packet(id, i); b.Destination = null;
            Assert.False((await missing.EvaluateAsync(At(b, i * Spacing(id)))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task IndependentBenignNearMissDoesNotAlert(string id)
    {
        var rule = Rule(id);
        for (var i = 0; i < Threshold(id) + 2; i++)
        {
            var packet = Packet(id, i % Threshold(id));
            switch (id)
            {
                case "R796": packet.ProcessName = "browser.exe"; break;
                case "R797": packet.Destination = "10.1.2.20"; break;
                case "R798": packet.Sni = "unrelated.example.org"; break;
                case "R799": packet.ProcessName = "browser.exe"; break;
                case "R800": packet.ProcessName = "browser.exe"; break;
                case "R801": packet.ApplicationProtocol = "HTTP"; break;
                case "R802": packet.DestinationPort = 102; break;
                case "R803": packet.ProcessName = "browser.exe"; break;
                case "R804": packet.DestinationPort = 162; break;
                case "R805": packet.DnsQname = "short.example.org"; break;
            }
            Assert.False((await rule.EvaluateAsync(At(packet, i * Spacing(id)))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task DuplicateReverseTimeAndExpiredWindowsFailClosed(string id)
    {
        var rule = Rule(id);
        var first = Packet(id, 0);
        await rule.EvaluateAsync(At(first, 10));
        for (var i = 1; i < Threshold(id); i++)
        {
            var duplicate = Packet(id, i); duplicate.Id = first.Id;
            Assert.False((await rule.EvaluateAsync(At(duplicate, 10 + i * Spacing(id)))).Matched);
        }
        Assert.False((await rule.EvaluateAsync(At(Packet(id, Threshold(id) - 1), 9))).Matched);

        var expired = Rule(id);
        await expired.EvaluateAsync(At(Packet(id, 0), 0));
        for (var i = 1; i < Threshold(id); i++)
            Assert.False((await expired.EvaluateAsync(At(Packet(id, i), 250 + i * Spacing(id)))).Matched);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task CooldownRecoveryAndEvidencePrivacy(string id)
    {
        var rule = Rule(id);
        var first = await Trigger(rule, id, 0);
        Assert.True(first.Matched);
        var encoded = JsonSerializer.Serialize(first.Events);
        Assert.DoesNotContain("PRIVATE-RAW-EVIDENCE-MARKER", encoded);
        Assert.DoesNotContain("telemetry.example.org", encoded);
        Assert.True((await Trigger(rule, id, 300)).Suppressed);
        Assert.True((await Trigger(rule, id, 940)).Matched);
    }

    [Fact]
    public async Task NeighboringNetworkPredicatesRemainDisjoint()
    {
        for (var i = 0; i < Ids.Length; i++)
        {
            var rule = Rule(Ids[i]);
            var other = Ids[(i + 1) % Ids.Length];
            for (var j = 0; j < Threshold(other) + 2; j++)
                Assert.False((await rule.EvaluateAsync(
                    At(Packet(other, j % Threshold(other)), j * Spacing(other)))).Matched);
        }
    }

    [Fact]
    public void RegistryContainsExactlyOneOfEachCandidateShadowRule()
    {
        var rules = RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count, rules.Select(r => r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var id in Ids)
        {
            var rule = Assert.Single(rules.Where(x => x.Descriptor.RuleId == id));
            var precision = Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(rule);
            Assert.Equal(RulePrecisionMaturity.Candidate, precision.PrecisionProfile.Maturity);
            Assert.Equal(RuleRuntimeMode.Shadow, precision.PrecisionProfile.DefaultMode);
        }
    }

    public static TheoryData<string> Cases => new()
    { "R796", "R797", "R798", "R799", "R800", "R801", "R802", "R803", "R804", "R805" };
}
