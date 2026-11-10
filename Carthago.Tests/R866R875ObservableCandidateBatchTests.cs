// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Authored before rule sources; no tests/builds executed.
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

public sealed class R866R875ObservableCandidateBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 10, 0, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids =
    { "R866", "R867", "R868", "R869", "R870", "R871", "R872", "R873", "R874", "R875" };

    private static IDetectionRule Rule(string id) => id switch
    {
        "R866" => new R866_MultiSubdomainSamePublicAnswerRule(),
        "R867" => new R867_SrvReplyThenMatchingTlsSniRule(),
        "R868" => new R868_SplitScopeSameNameAReplyRule(),
        "R869" => new R869_PublicRpcEndpointThenDynamicPortRule(),
        "R870" => new R870_HostdPublicHttpPollBurstRule(),
        "R871" => new R871_ModbusMultiDevicePayloadWalkRule(),
        "R872" => new R872_EmbeddedSnapshotEndpointPairRule(),
        "R873" => new R873_SsdpMulticastThenDeviceHttpSynRule(),
        "R874" => new R874_PrivateOtTcpSynBurstRule(),
        "R875" => new R875_PublicDnp3SynThenPayloadRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static int Threshold(string id) => id switch
    {
        "R866" or "R871" => id == "R866" ? 3 : 4,
        "R870" => 4,
        "R874" => 8,
        _ => 2
    };

    private static TrafficRecord Packet(string id, int stage)
    {
        var r = new TrafficRecord
        {
            Id = Guid.NewGuid(), IpVersion = 4, Source = "10.1.1.10", Destination = "10.1.2.45",
            Protocol = "TCP", IsTcp = true, SourcePort = 51000, DestinationPort = 502,
            TcpFlags = 0x02, L4Len = 0, Length = 40, ProcessName = "modpoll", ProcessId = 312,
            Info = "PRIVATE-RAW-EVIDENCE-MARKER"
        };
        switch (id)
        {
            case "R866":
                DnsReply(r, $"app{stage + 1}.corp.example", "A", "8.8.8.8");
                break;
            case "R867":
                if (stage == 0) DnsReply(r, "_ldap._tcp.corp.example", "SRV", "service.example.net");
                else { r.Destination = "8.8.8.8"; Tls(r, "service.example.net"); }
                break;
            case "R868":
                DnsReply(r, "portal.corp.example", "A", stage == 0 ? "10.4.5.6" : "8.8.8.8");
                r.Destination = stage == 0 ? "10.1.1.10" : "10.1.1.11";
                break;
            case "R869":
                r.Source = "8.8.8.8"; r.DestinationPort = stage == 0 ? 135 : 50010;
                r.ProcessName = null; r.ProcessId = 0;
                break;
            case "R870":
                r.Destination = "8.8.8.8"; r.ProcessName = "hostd";
                Http(r, "GET", "/api/v1/poll", "status.example.net");
                break;
            case "R871":
                r.Destination = "10.1.2." + (21 + stage); Data(r, 120);
                break;
            case "R872":
                r.Source = "8.8.8.8";
                Http(r, "GET", stage == 0 ? "/snapshot.jpg" : "/stream.mjpg", "camera.example.net");
                break;
            case "R873":
                if (stage == 0) { Udp(r, "239.255.255.250", 1900, 180); }
                else { r.DestinationPort = 8008; }
                break;
            case "R874":
                r.DestinationPort = 502;
                break;
            case "R875":
                r.Source = "8.8.8.8"; r.DestinationPort = 20000;
                if (stage == 1) Data(r, 480);
                break;
        }
        return r;
    }

    private static void Data(TrafficRecord r, int bytes)
    { r.TcpFlags = 0x18; r.L4Len = bytes; r.Length = bytes + 40; }

    private static void Tls(TrafficRecord r, string sni)
    { Data(r, 600); r.DestinationPort = 443; r.TlsVersion = "TLS1.3"; r.Sni = sni; }

    private static void Udp(TrafficRecord r, string peer, int port, int bytes)
    {
        r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP"; r.TcpFlags = null;
        r.Destination = peer; r.DestinationPort = port; r.L4Len = bytes; r.Length = bytes + 28;
    }

    private static void DnsReply(TrafficRecord r, string qname, string qtype, string answer)
    {
        Udp(r, "10.1.1.10", 53000, 180); r.Source = "10.1.2.53"; r.SourcePort = 53;
        r.ApplicationProtocol = "DNS"; r.DnsIsResponse = true;
        r.DnsQname = qname; r.DnsQtype = qtype; r.DnsAnswers = answer; r.DnsTtl = 300;
    }

    private static void Http(TrafficRecord r, string method, string uri, string host)
    {
        Data(r, 550); r.DestinationPort = 80; r.ApplicationProtocol = "HTTP";
        r.HttpMethod = method; r.HttpUri = uri; r.HttpHost = host;
    }

    private static RuleEvaluationContext At(TrafficRecord r, double sec)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(sec));

    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, double start)
    {
        RuleEvaluationResult? result = null;
        for (var i = 0; i < Threshold(id); i++)
            result = await rule.EvaluateAsync(At(Packet(id, i), start + i * 3));
        return result!;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task PositiveTypedPacketShapeMatchesWithoutLeakingRawInfo(string id)
    {
        var result = await Trigger(Rule(id), id, 0);
        Assert.True(result.Matched);
        Assert.DoesNotContain("PRIVATE-RAW-EVIDENCE-MARKER", JsonSerializer.Serialize(result.Events));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task MissingDestinationAndContradictoryTransportFailClosed(string id)
    {
        var missing = Rule(id); var contradiction = Rule(id);
        for (var i = 0; i < Threshold(id); i++)
        {
            var absent = Packet(id, i); absent.Destination = null;
            Assert.False((await missing.EvaluateAsync(At(absent, 3 * i))).Matched);
            var dual = Packet(id, i); dual.IsTcp = dual.IsUdp = true;
            Assert.False((await contradiction.EvaluateAsync(At(dual, 3 * i))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task NearbyBenignShapeDoesNotMatch(string id)
    {
        var rule = Rule(id);
        for (var i = 0; i < Threshold(id) + 2; i++)
        {
            var packet = Packet(id, i % Threshold(id));
            switch (id)
            {
                case "R866": packet.DnsAnswers = "10.0.0.5"; break;
                case "R867": packet.DnsQtype = "A"; packet.Sni = "other.example.net"; break;
                case "R868": packet.DnsAnswers = "10.0.0.5"; break;
                case "R869": packet.DestinationPort = 3389; break;
                case "R870": packet.ProcessName = "explorer.exe"; break;
                case "R871": packet.Destination = "10.1.2.21"; break;
                case "R872": packet.HttpUri = "/index.html"; break;
                case "R873": packet.DestinationPort = 9999; break;
                case "R874": packet.DestinationPort = 22; break;
                case "R875": packet.DestinationPort = 20001; break;
            }
            Assert.False((await rule.EvaluateAsync(At(packet, i * 3))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task DuplicateIdsAndExpiredFirstObservationCannotComplete(string id)
    {
        var duplicateRule = Rule(id); var first = Packet(id, 0);
        await duplicateRule.EvaluateAsync(At(first, 0));
        for (var i = 1; i < Threshold(id); i++)
        {
            var duplicate = Packet(id, i); duplicate.Id = first.Id;
            Assert.False((await duplicateRule.EvaluateAsync(At(duplicate, i * 3))).Matched);
        }
        var expired = Rule(id);
        await expired.EvaluateAsync(At(Packet(id, 0), 0));
        for (var i = 1; i < Threshold(id); i++)
            Assert.False((await expired.EvaluateAsync(At(Packet(id, i), 260 + i * 3))).Matched);
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
    public async Task DifferentSrvHostnameDoesNotCorrelate()
    {
        var rule = Rule("R867");
        await rule.EvaluateAsync(At(Packet("R867", 0), 0));
        var mismatch = Packet("R867", 1); mismatch.Sni = "other.example.net";
        Assert.False((await rule.EvaluateAsync(At(mismatch, 3))).Matched);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task ReverseUtcTimeCannotCompleteAnObservation(string id)
    {
        var rule = Rule(id);
        await rule.EvaluateAsync(At(Packet(id, 0), 90));
        for (var i = 1; i < Threshold(id); i++)
            Assert.False((await rule.EvaluateAsync(At(Packet(id, i), 90 - i * 3))).Matched);
    }

    [Fact]
    public async Task SplitScopeRequiresDifferentClients()
    {
        var rule = Rule("R868");
        await rule.EvaluateAsync(At(Packet("R868", 0), 0));
        var sameClient = Packet("R868", 1); sameClient.Destination = "10.1.1.10";
        Assert.False((await rule.EvaluateAsync(At(sameClient, 3))).Matched);
    }

    [Fact]
    public async Task NeighborRulesNeverShareStateOrConditions()
    {
        for (var i = 0; i < Ids.Length; i++)
        {
            var other = Ids[(i + 1) % Ids.Length]; var target = Rule(Ids[i]);
            for (var j = 0; j < Threshold(other) + 2; j++)
                Assert.False((await target.EvaluateAsync(At(Packet(other, j % Threshold(other)), j * 3))).Matched);
        }
    }

    [Fact]
    public void RegistryHasTenUniqueCandidateShadowRules()
    {
        var rules = RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count, rules.Select(r => r.Descriptor.RuleId)
            .Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var id in Ids)
        {
            var rule = Assert.Single(rules.Where(r => r.Descriptor.RuleId == id));
            var profile = Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(rule).PrecisionProfile;
            Assert.Equal(RulePrecisionMaturity.Candidate, profile.Maturity);
            Assert.Equal(RuleRuntimeMode.Shadow, profile.DefaultMode);
        }
    }

    public static TheoryData<string> Cases => new()
    { "R866", "R867", "R868", "R869", "R870", "R871", "R872", "R873", "R874", "R875" };
}
