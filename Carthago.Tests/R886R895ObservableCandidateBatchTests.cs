// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Test source authored before detectors; no test/build execution.
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

public sealed class R886R895ObservableCandidateBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 11, 0, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids =
    { "R886", "R887", "R888", "R889", "R890", "R891", "R892", "R893", "R894", "R895" };

    private static IDetectionRule Rule(string id) => id switch
    {
        "R886" => new R886_SshIngressThenInternalSmbSynRule(),
        "R887" => new R887_IdeProcessPublicTlsPeerPairRule(),
        "R888" => new R888_EsxiManagementPublicTlsPeerPairRule(),
        "R889" => new R889_HostdVpxaTlsCadenceRule(),
        "R890" => new R890_Rundll32PublicTlsPeerPairRule(),
        "R891" => new R891_PublicVncSynThenPayloadRule(),
        "R892" => new R892_BroadcastUdpNineThenRdpSynRule(),
        "R893" => new R893_PowershellDnsQueryThenSniTlsRule(),
        "R894" => new R894_PublicSshThenWebApiProbeRule(),
        "R895" => new R895_PrivateIndustrialDualPortSynRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static int Threshold(string id) => id == "R889" ? 4 : 2;
    private static double Step(string id) => id == "R889" ? 10 : 3;

    private static TrafficRecord Packet(string id, int stage)
    {
        var r = new TrafficRecord
        {
            Id = Guid.NewGuid(), IpVersion = 4, Source = "10.1.1.10", Destination = "10.1.2.45",
            SourcePort = 51000, DestinationPort = 443, IsTcp = true, Protocol = "TCP",
            TcpFlags = 0x02, L4Len = 0, Length = 40,
            ProcessId = 310, ProcessName = "code.exe", Info = "SECRET-RAW-INFO-MARKER"
        };
        switch (id)
        {
            case "R886":
                if (stage == 0) { r.Source = "8.8.8.8"; r.DestinationPort = 22; }
                else { r.Source = "10.1.2.45"; r.Destination = "10.1.3.77"; r.DestinationPort = 445; }
                break;
            case "R887":
                r.ProcessName = "code.exe"; r.Destination = stage == 0 ? "8.8.8.8" : "9.9.9.9";
                Tls(r, 443, "tunnel.example.net", 680); break;
            case "R888":
                r.ProcessName = "vpxa"; r.Destination = stage == 0 ? "8.8.8.8" : "9.9.9.9";
                Tls(r, 443, "mgmt.example.net", 730); break;
            case "R889":
                r.ProcessName = "hostd"; r.Destination = "8.8.8.8";
                Tls(r, 8443, "hostsync.example.net", 640 + stage * 4); break;
            case "R890":
                r.ProcessName = "rundll32.exe";
                r.Destination = stage == 0 ? "8.8.8.8" : "9.9.9.9";
                Tls(r, 9443, "service.example.net", 680); break;
            case "R891":
                r.Source = "8.8.8.8"; r.DestinationPort = 5900;
                if (stage == 1) Data(r, 520); break;
            case "R892":
                if (stage == 0) Udp(r, "10.1.1.255", 9, 102);
                else r.DestinationPort = 3389;
                break;
            case "R893":
                r.ProcessName = "powershell.exe";
                if (stage == 0)
                {
                    Udp(r, "10.1.2.53", 53, 120); r.ApplicationProtocol = "DNS";
                    r.DnsQname = "updater.example.net"; r.DnsQtype = "A";
                }
                else { r.Destination = "8.8.8.8"; Tls(r, 443, "updater.example.net", 720); }
                break;
            case "R894":
                r.Source = "8.8.8.8";
                if (stage == 0) r.DestinationPort = 22;
                else Http(r, "POST", "/api/login");
                break;
            case "R895":
                r.DestinationPort = stage == 0 ? 502 : 44818;
                break;
        }
        return r;
    }

    private static void Data(TrafficRecord r, int size)
    { r.TcpFlags = 0x18; r.L4Len = size; r.Length = size + 40; }
    private static void Tls(TrafficRecord r, int port, string sni, int size)
    { Data(r, size); r.DestinationPort = port; r.TlsVersion = "TLS1.3"; r.Sni = sni; }
    private static void Http(TrafficRecord r, string method, string uri)
    { Data(r, 520); r.DestinationPort = 80; r.ApplicationProtocol = "HTTP";
      r.HttpMethod = method; r.HttpUri = uri; r.HttpHost = "service.internal"; }
    private static void Udp(TrafficRecord r, string dest, int port, int bytes)
    { r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP"; r.TcpFlags = null;
      r.Destination = dest; r.DestinationPort = port; r.L4Len = bytes; r.Length = bytes + 28; }
    private static RuleEvaluationContext At(TrafficRecord r, double seconds)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));
    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, double start)
    {
        RuleEvaluationResult? result = null;
        for (var i = 0; i < Threshold(id); i++)
            result = await rule.EvaluateAsync(At(Packet(id, i), start + i * Step(id)));
        return result!;
    }

    [Theory]
    [InlineData("R889")]
    public async Task MissingPayloadLengthFailsClosed(string id)
    {
        var rule = Rule(id);
        for (var i = 0; i < Threshold(id); i++)
        {
            var packet = Packet(id, i);
            packet.L4Len = null;
            Assert.False((await rule.EvaluateAsync(At(packet, i * Step(id)))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task TypedPositiveAndNoRawInfo(string id)
    {
        var result = await Trigger(Rule(id), id, 0);
        Assert.True(result.Matched);
        Assert.DoesNotContain("SECRET-RAW-INFO-MARKER", JsonSerializer.Serialize(result.Events));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task MissingPeersOrContradictoryTransportFailClosed(string id)
    {
        var missing = Rule(id); var contradictory = Rule(id);
        for (var i = 0; i < Threshold(id); i++)
        {
            var a = Packet(id, i); a.Destination = null;
            Assert.False((await missing.EvaluateAsync(At(a, i * Step(id)))).Matched);
            var b = Packet(id, i); b.IsTcp = b.IsUdp = true;
            Assert.False((await contradictory.EvaluateAsync(At(b, i * Step(id)))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task BenignNearMissFailsClosed(string id)
    {
        var rule = Rule(id);
        for (var i = 0; i < Threshold(id) + 2; i++)
        {
            var r = Packet(id, i % Threshold(id));
            switch (id)
            {
                case "R886": r.DestinationPort = 8080; break;
                case "R887": case "R888": case "R889": case "R890": r.ProcessName = "explorer.exe"; break;
                case "R891": r.DestinationPort = 5901; break;
                case "R892": r.DestinationPort = 3390; break;
                case "R893": r.ProcessName = "explorer.exe"; break;
                case "R894": r.DestinationPort = 8080; break;
                case "R895": r.DestinationPort = 8080; break;
            }
            Assert.False((await rule.EvaluateAsync(At(r, i * Step(id)))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task DuplicateIdReversedTimeAndExpiredWindowCannotComplete(string id)
    {
        var first = Packet(id, 0); var duplicate = Rule(id);
        await duplicate.EvaluateAsync(At(first, 0));
        for (var i = 1; i < Threshold(id); i++)
        {
            var copy = Packet(id, i); copy.Id = first.Id;
            Assert.False((await duplicate.EvaluateAsync(At(copy, i * Step(id)))).Matched);
        }
        var reverse = Rule(id);
        await reverse.EvaluateAsync(At(Packet(id, 0), 120));
        for (var i = 1; i < Threshold(id); i++)
            Assert.False((await reverse.EvaluateAsync(At(Packet(id, i), 120 - i * Step(id)))).Matched);
        var expired = Rule(id);
        await expired.EvaluateAsync(At(Packet(id, 0), 0));
        for (var i = 1; i < Threshold(id); i++)
            Assert.False((await expired.EvaluateAsync(At(Packet(id, i), 280 + i * Step(id)))).Matched);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task CooldownSuppressesAndRecovers(string id)
    {
        var rule = Rule(id);
        Assert.True((await Trigger(rule, id, 0)).Matched);
        Assert.True((await Trigger(rule, id, 300)).Suppressed);
        Assert.True((await Trigger(rule, id, 950)).Matched);
    }

    [Fact]
    public async Task TlsPeerPairRequiresDifferentPublicAddresses()
    {
        foreach (var id in new[] { "R887", "R888", "R890" })
        {
            var rule = Rule(id);
            await rule.EvaluateAsync(At(Packet(id, 0), 0));
            var second = Packet(id, 1); second.Destination = "8.8.8.8";
            Assert.False((await rule.EvaluateAsync(At(second, 3))).Matched);
        }
    }

    [Fact]
    public async Task DnsSniCorrelationRequiresMatchingDomain()
    {
        var rule = Rule("R893");
        await rule.EvaluateAsync(At(Packet("R893", 0), 0));
        var other = Packet("R893", 1); other.Sni = "other.example.net";
        Assert.False((await rule.EvaluateAsync(At(other, 3))).Matched);
    }

    [Fact]
    public async Task CadenceNeedsMinimumSpacing()
    {
        var rule = Rule("R889");
        for (var i = 0; i < 4; i++)
            Assert.False((await rule.EvaluateAsync(At(Packet("R889", i), i))).Matched);
    }

    [Fact]
    public async Task AdjacentRulesStayIndependent()
    {
        for (var i = 0; i < Ids.Length; i++)
        {
            var otherId = Ids[(i + 1) % Ids.Length]; var rule = Rule(Ids[i]);
            for (var j = 0; j < Threshold(otherId) + 2; j++)
                Assert.False((await rule.EvaluateAsync(At(Packet(otherId, j % Threshold(otherId)), j * Step(otherId)))).Matched);
        }
    }

    [Fact]
    public void RegistryHasUniqueCandidateShadowRules()
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

    public static TheoryData<string> Cases => new()
    { "R886", "R887", "R888", "R889", "R890", "R891", "R892", "R893", "R894", "R895" };
}
