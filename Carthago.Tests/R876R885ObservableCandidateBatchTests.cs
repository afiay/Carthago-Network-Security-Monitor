// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Authored before detector code; no tests/builds executed.
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

public sealed class R876R885ObservableCandidateBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 11, 0, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids =
    { "R876", "R877", "R878", "R879", "R880", "R881", "R882", "R883", "R884", "R885" };

    private static IDetectionRule Rule(string id) => id switch
    {
        "R876" => new R876_FastFluxDnsReplyThenAnswerSynRule(),
        "R877" => new R877_DockerApiCreateThenStartRequestRule(),
        "R878" => new R878_PublicSshSynThenPayloadRule(),
        "R879" => new R879_PublicTelnetThenBusyboxTlsRule(),
        "R880" => new R880_PublicTraversalThenAdminPostRule(),
        "R881" => new R881_PublicFtpThenPrivateTftpRule(),
        "R882" => new R882_EsxiGetThenOtherPeerPostRule(),
        "R883" => new R883_VmwareVmxPublicTlsPeerFanoutRule(),
        "R884" => new R884_GitPrivateObjectGetFanoutRule(),
        "R885" => new R885_PublicCgiPostThenBashTlsRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static int Threshold(string id) => id switch
    {
        "R876" or "R884" => 4,
        "R883" => 3,
        _ => 2
    };

    private static TrafficRecord Packet(string id, int stage)
    {
        var r = new TrafficRecord
        {
            Id = Guid.NewGuid(), IpVersion = 4, Source = "10.1.1.10", Destination = "10.1.2.45",
            Protocol = "TCP", IsTcp = true, SourcePort = 51000, DestinationPort = 502,
            TcpFlags = 0x02, L4Len = 0, Length = 40, ProcessName = "git.exe", ProcessId = 312,
            Info = "PRIVATE-RAW-EVIDENCE-MARKER"
        };
        switch (id)
        {
            case "R876":
                if (stage < 3) DnsReply(r, "edge.example.net",
                    new[] { "8.8.8.8", "9.9.9.9", "1.1.1.1" }[stage], 10);
                else { r.Destination = "1.1.1.1"; r.DestinationPort = 443; }
                break;
            case "R877":
                Http(r, "POST", stage == 0 ? "/containers/create" : "/containers/abc123/start",
                    "docker.internal"); r.DestinationPort = 2375;
                break;
            case "R878":
                r.Source = "8.8.8.8"; r.DestinationPort = 22;
                if (stage == 1) Data(r, 540);
                break;
            case "R879":
                if (stage == 0) { r.Source = "8.8.8.8"; r.DestinationPort = 23; }
                else
                {
                    r.Source = "10.1.2.45"; r.Destination = "9.9.9.9";
                    r.ProcessName = "busybox"; Tls(r, 8443, "relay.example.net", 600);
                }
                break;
            case "R880":
                r.Source = "8.8.8.8"; Http(r, stage == 0 ? "GET" : "POST",
                    stage == 0 ? "/cgi-bin/.%2e/" : "/admin/upload", "web.example.net");
                break;
            case "R881":
                if (stage == 0) { r.Source = "8.8.8.8"; r.DestinationPort = 21; }
                else { r.Source = "10.1.2.45"; Udp(r, "10.1.3.99", 69, 500); }
                break;
            case "R882":
                r.Source = "10.1.2.45"; r.Destination = stage == 0 ? "8.8.8.8" : "9.9.9.9";
                r.ProcessName = stage == 0 ? "esxcli" : "busybox";
                Http(r, stage == 0 ? "GET" : "POST",
                    stage == 0 ? "/download/bootstrap.sh" : "/api/checkin", "service.example.net");
                break;
            case "R883":
                r.ProcessName = "vmware-vmx"; r.Destination = new[] { "8.8.8.8", "9.9.9.9", "1.1.1.1" }[stage];
                Tls(r, 8443, "updates.example.net", 720);
                break;
            case "R884":
                r.ProcessName = "git"; Http(r, "GET",
                    "/private-repo.git/objects/ab/object" + stage, "git.internal");
                break;
            case "R885":
                if (stage == 0)
                {
                    r.Source = "8.8.8.8"; Http(r, "POST", "/cgi-bin/diag.cgi", "plc.example.net");
                }
                else
                {
                    r.Source = "10.1.2.45"; r.Destination = "9.9.9.9";
                    r.ProcessName = "bash"; Tls(r, 8443, "relay.example.net", 690);
                }
                break;
        }
        return r;
    }

    private static void Data(TrafficRecord r, int bytes)
    { r.TcpFlags = 0x18; r.L4Len = bytes; r.Length = bytes + 40; }

    private static void Tls(TrafficRecord r, int port, string sni, int bytes)
    {
        Data(r, bytes); r.DestinationPort = port; r.TlsVersion = "TLS1.3"; r.Sni = sni;
        r.HttpMethod = r.HttpUri = r.ApplicationProtocol = null;
    }

    private static void Udp(TrafficRecord r, string peer, int port, int bytes)
    {
        r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP"; r.TcpFlags = null;
        r.Destination = peer; r.DestinationPort = port; r.L4Len = bytes; r.Length = bytes + 28;
    }

    private static void DnsReply(TrafficRecord r, string name, string answer, int ttl)
    {
        Udp(r, "10.1.1.10", 53000, 150); r.Source = "10.1.2.53"; r.SourcePort = 53;
        r.ApplicationProtocol = "DNS"; r.DnsIsResponse = true;
        r.DnsQname = name; r.DnsQtype = "A"; r.DnsAnswers = answer; r.DnsTtl = ttl;
    }

    private static void Http(TrafficRecord r, string method, string uri, string host)
    {
        Data(r, 560); r.DestinationPort = 80; r.ApplicationProtocol = "HTTP";
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
    public async Task TypedPositiveMatchesWithoutRawInfoDisclosure(string id)
    {
        var result = await Trigger(Rule(id), id, 0);
        Assert.True(result.Matched);
        Assert.DoesNotContain("PRIVATE-RAW-EVIDENCE-MARKER", JsonSerializer.Serialize(result.Events));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task MissingPeerOrContradictoryTransportFailsClosed(string id)
    {
        var noPeer = Rule(id); var wrongTransport = Rule(id);
        for (var i = 0; i < Threshold(id); i++)
        {
            var a = Packet(id, i); a.Destination = null;
            Assert.False((await noPeer.EvaluateAsync(At(a, i * 3))).Matched);
            var b = Packet(id, i); b.IsTcp = b.IsUdp = true;
            Assert.False((await wrongTransport.EvaluateAsync(At(b, i * 3))).Matched);
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
                case "R876": r.DnsTtl = 600; r.DestinationPort = 5000; break;
                case "R877": r.HttpUri = "/containers/json"; break;
                case "R878": r.DestinationPort = 2222; break;
                case "R879": r.DestinationPort = 2222; r.ProcessName = "explorer"; break;
                case "R880": r.HttpUri = "/index.html"; break;
                case "R881": r.DestinationPort = 70; break;
                case "R882": r.ProcessName = "explorer"; break;
                case "R883": r.ProcessName = "explorer"; break;
                case "R884": r.HttpUri = "/index.html"; break;
                case "R885": r.HttpUri = "/index.html"; r.ProcessName = "explorer"; break;
            }
            Assert.False((await rule.EvaluateAsync(At(r, i * 3))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task DuplicateIdsReverseTimeAndExpiryCannotComplete(string id)
    {
        var dup = Rule(id); var first = Packet(id, 0);
        await dup.EvaluateAsync(At(first, 0));
        for (var i = 1; i < Threshold(id); i++)
        {
            var copy = Packet(id, i); copy.Id = first.Id;
            Assert.False((await dup.EvaluateAsync(At(copy, i * 3))).Matched);
        }
        var reverse = Rule(id);
        await reverse.EvaluateAsync(At(Packet(id, 0), 90));
        for (var i = 1; i < Threshold(id); i++)
            Assert.False((await reverse.EvaluateAsync(At(Packet(id, i), 90 - i * 3))).Matched);
        var expired = Rule(id);
        await expired.EvaluateAsync(At(Packet(id, 0), 0));
        for (var i = 1; i < Threshold(id); i++)
            Assert.False((await expired.EvaluateAsync(At(Packet(id, i), 260 + i * 3))).Matched);
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
    public async Task FastFluxSynMustTargetLastDnsAnswer()
    {
        var rule = Rule("R876");
        for (var i = 0; i < 3; i++)
            await rule.EvaluateAsync(At(Packet("R876", i), 3 * i));
        var other = Packet("R876", 3); other.Destination = "4.4.4.4";
        Assert.False((await rule.EvaluateAsync(At(other, 9))).Matched);
    }

    [Fact]
    public async Task EsxiSecondHttpLegMustTargetOtherPeer()
    {
        var rule = Rule("R882");
        await rule.EvaluateAsync(At(Packet("R882", 0), 0));
        var samePeer = Packet("R882", 1); samePeer.Destination = "8.8.8.8";
        Assert.False((await rule.EvaluateAsync(At(samePeer, 3))).Matched);
    }

    [Fact]
    public async Task NeighboringRulesNeverSharePredicateOrState()
    {
        for (var i = 0; i < Ids.Length; i++)
        {
            var next = Ids[(i + 1) % Ids.Length]; var rule = Rule(Ids[i]);
            for (var j = 0; j < Threshold(next) + 2; j++)
                Assert.False((await rule.EvaluateAsync(At(Packet(next, j % Threshold(next)), 3 * j))).Matched);
        }
    }

    [Fact]
    public void RegistryPreservesUniqueCandidateShadowInstances()
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
    { "R876", "R877", "R878", "R879", "R880", "R881", "R882", "R883", "R884", "R885" };
}
