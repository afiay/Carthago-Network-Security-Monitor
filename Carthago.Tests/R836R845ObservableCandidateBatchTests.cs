// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored before implementation; no tests executed.
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

public sealed class R836R845ObservableCandidateBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 10, 0, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids = { "R836", "R837", "R838", "R839", "R840", "R841", "R842", "R843", "R844", "R845" };

    private static IDetectionRule Rule(string id) => id switch
    {
        "R836" => new R836_PostgresInboundThenServiceTlsRule(),
        "R837" => new R837_ConflictingResolverAnswerThenSynRule(),
        "R838" => new R838_PackageRegistryThenOtherPeerTlsRule(),
        "R839" => new R839_TraversalGetThenWebWorkerTlsRule(),
        "R840" => new R840_PublicRepeatedSamePathGetRule(),
        "R841" => new R841_BrowserScriptGetThenPythonTlsRule(),
        "R842" => new R842_ScriptPublicApiTlsBidirectionalRule(),
        "R843" => new R843_ProcessPeerTlsVersionRegressionRule(),
        "R844" => new R844_LowTtlDnsAnswerChurnRule(),
        "R845" => new R845_ScpDistinctInternalSshPeersRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static int Count(string id) => id switch { "R840" => 8, "R837" or "R844" => 3, _ => 2 };

    private static TrafficRecord Packet(string id, int stage)
    {
        var r = new TrafficRecord
        {
            Id = Guid.NewGuid(), IpVersion = 4, Protocol = "TCP", IsTcp = true,
            Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000,
            DestinationPort = 443, TcpFlags = 0x18, L4Len = 700, Length = 740,
            ProcessId = 412, ProcessName = "powershell.exe", TlsVersion = "TLS1.3",
            Sni = "api.example.net", Info = "PRIVATE-RAW-EVIDENCE-MARKER"
        };
        switch (id)
        {
            case "R836":
                if (stage == 0) { Syn(r, "8.8.8.8", "10.1.1.10", 55000, 5432); r.ProcessId = 0; r.ProcessName = null; }
                else { r.ProcessName = "postgres"; r.Destination = "9.9.9.9"; Tls(r, 8443, "relay.example.net"); }
                break;
            case "R837":
                if (stage < 2) DnsResponse(r, stage == 0 ? "8.8.8.8" : "9.9.9.9", "10.1.1.10",
                    "repo.example.net", stage == 0 ? "1.1.1.1" : "1.0.0.1", 60);
                else Syn(r, "10.1.1.10", "1.0.0.1", 51000, 443);
                break;
            case "R838":
                r.ProcessName = "npm"; r.Destination = stage == 0 ? "8.8.8.8" : "9.9.9.9";
                Tls(r, stage == 0 ? 443 : 8443, stage == 0 ? "registry.npmjs.org" : "relay.example.net");
                break;
            case "R839":
                if (stage == 0) { Http(r, "8.8.8.8", "10.1.1.10", "/%2e%2e/%2e%2e/etc/passwd", "target.example.net"); r.ProcessId = 0; r.ProcessName = null; }
                else { r.ProcessName = "w3wp.exe"; r.Destination = "9.9.9.9"; Tls(r, 8443, "relay.example.net"); }
                break;
            case "R840":
                Http(r, "8.8.8.8", "10.1.1.10", "/api/status", "target.example.net");
                r.SourcePort = 55000 + stage; r.ProcessName = null; r.ProcessId = 0;
                break;
            case "R841":
                if (stage == 0) { r.ProcessName = "firefox"; Http(r, "10.1.1.10", "8.8.8.8", "/assets/runtime.js", "cdn.example.net"); }
                else { r.ProcessName = "python3"; r.Destination = "9.9.9.9"; Tls(r, 8443, "relay.example.net"); }
                break;
            case "R842":
                if (stage == 0) { r.ProcessName = "powershell.exe"; Tls(r, 443, "api.github.com"); }
                else { r.Source = "8.8.8.8"; r.Destination = "10.1.1.10"; r.SourcePort = 443; r.DestinationPort = 51000; r.ProcessId = 0; r.ProcessName = null; r.TlsVersion = null; r.Sni = null; }
                break;
            case "R843":
                r.ProcessName = "curl"; Tls(r, 443, "api.example.net");
                r.TlsVersion = stage == 0 ? "TLS1.3" : "TLS1.0";
                break;
            case "R844":
                DnsResponse(r, "8.8.8.8", "10.1.1.10", "edge.example.net",
                    stage switch { 0 => "1.1.1.1", 1 => "1.0.0.1", _ => "9.9.9.9" }, 15);
                break;
            case "R845":
                r.ProcessName = "scp"; r.Destination = stage == 0 ? "10.2.1.11" : "10.3.1.12";
                r.DestinationPort = 22; r.TlsVersion = null; r.Sni = null;
                break;
        }
        return r;
    }

    private static void Syn(TrafficRecord r, string src, string dst, int sourcePort, int destPort)
    {
        r.Source = src; r.Destination = dst; r.SourcePort = sourcePort; r.DestinationPort = destPort;
        r.TcpFlags = 0x02; r.L4Len = 0; r.Length = 40;
        r.TlsVersion = r.Sni = r.ApplicationProtocol = r.HttpMethod = r.HttpUri = null;
    }

    private static void Tls(TrafficRecord r, int port, string sni)
    {
        r.DestinationPort = port; r.TcpFlags = 0x18; r.L4Len = 700; r.Length = 740;
        r.TlsVersion = "TLS1.3"; r.Sni = sni; r.ApplicationProtocol = r.HttpMethod = r.HttpUri = null;
    }

    private static void Http(TrafficRecord r, string src, string dst, string uri, string host)
    {
        r.Source = src; r.Destination = dst; r.SourcePort = 55000; r.DestinationPort = 80;
        r.TcpFlags = 0x18; r.L4Len = 400; r.Length = 440;
        r.TlsVersion = r.Sni = null; r.ApplicationProtocol = "HTTP";
        r.HttpMethod = "GET"; r.HttpUri = uri; r.HttpHost = host;
    }

    private static void DnsResponse(TrafficRecord r, string resolver, string client, string name, string answer, int ttl)
    {
        r.Source = resolver; r.Destination = client; r.Protocol = "UDP";
        r.IsTcp = false; r.IsUdp = true; r.TcpFlags = null; r.SourcePort = 53; r.DestinationPort = 53000;
        r.L4Len = 128; r.Length = 156; r.ProcessName = null; r.ProcessId = 0;
        r.TlsVersion = r.Sni = null; r.ApplicationProtocol = "DNS";
        r.DnsIsResponse = true; r.DnsQtype = "A"; r.DnsQname = name;
        r.DnsAnswers = answer; r.DnsTtl = ttl;
    }

    private static RuleEvaluationContext At(TrafficRecord packet, double seconds)
        => new(packet, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    private static async Task<RuleEvaluationResult> Run(IDetectionRule rule, string id, double start)
    {
        RuleEvaluationResult? result = null;
        for (var i = 0; i < Count(id); i++)
            result = await rule.EvaluateAsync(At(Packet(id, i), start + i * 2));
        return result!;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task TypedPositiveIsSourceCandidateOnly(string id)
    {
        var result = await Run(Rule(id), id, 0);
        Assert.True(result.Matched);
        Assert.DoesNotContain("PRIVATE-RAW-EVIDENCE-MARKER", JsonSerializer.Serialize(result.Events));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task ContradictoryAndMissingIpEvidenceFailClosed(string id)
    {
        var contradictory = Rule(id); var missing = Rule(id);
        for (var i = 0; i < Count(id); i++)
        {
            var bad = Packet(id, i); bad.IsTcp = bad.IsUdp = true;
            Assert.False((await contradictory.EvaluateAsync(At(bad, i * 2))).Matched);
            var noIp = Packet(id, i); noIp.Destination = null;
            Assert.False((await missing.EvaluateAsync(At(noIp, i * 2))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task NearbyBenignSequenceCannotMatch(string id)
    {
        var rule = Rule(id);
        for (var i = 0; i < Count(id) + 2; i++)
        {
            var r = Packet(id, i % Count(id));
            switch (id)
            {
                case "R836": r.ProcessName = "psql"; r.DestinationPort = 5433; break;
                case "R837": r.DnsAnswers = "1.1.1.1"; r.Destination = i % Count(id) == 2 ? "1.1.1.1" : r.Destination; break;
                case "R838": r.ProcessName = "explorer.exe"; break;
                case "R839": r.HttpUri = "/static/index.html"; r.ProcessName = "explorer.exe"; break;
                case "R840": r.HttpUri = "/api/status/" + i; break;
                case "R841": r.ProcessName = "explorer.exe"; break;
                case "R842": r.ProcessName = "explorer.exe"; r.SourcePort = 444; break;
                case "R843": r.TlsVersion = "TLS1.3"; break;
                case "R844": r.DnsTtl = 3600; break;
                case "R845": r.ProcessName = "explorer.exe"; break;
            }
            Assert.False((await rule.EvaluateAsync(At(r, i * 2))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task RepeatedPacketIdAndExpiredFirstStepAreRejected(string id)
    {
        var repeated = Rule(id); var initial = Packet(id, 0);
        await repeated.EvaluateAsync(At(initial, 0));
        for (var i = 1; i < Count(id); i++)
        {
            var r = Packet(id, i); r.Id = initial.Id;
            Assert.False((await repeated.EvaluateAsync(At(r, i * 2))).Matched);
        }
        var expired = Rule(id);
        await expired.EvaluateAsync(At(Packet(id, 0), 0));
        for (var i = 1; i < Count(id); i++)
            Assert.False((await expired.EvaluateAsync(At(Packet(id, i), 250 + i * 2))).Matched);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task CooldownSuppressesThenRecovers(string id)
    {
        var rule = Rule(id);
        Assert.True((await Run(rule, id, 0)).Matched);
        Assert.True((await Run(rule, id, 300)).Suppressed);
        Assert.True((await Run(rule, id, 950)).Matched);
    }

    [Fact]
    public async Task DnsConflictRequiresDifferentResolversAndAnswerThenActualSyn()
    {
        var rule = Rule("R837");
        await rule.EvaluateAsync(At(Packet("R837", 0), 0));
        var sameResolver = Packet("R837", 1); sameResolver.Source = "8.8.8.8";
        Assert.False((await rule.EvaluateAsync(At(sameResolver, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Packet("R837", 2), 4))).Matched);
        var other = Rule("R837");
        await other.EvaluateAsync(At(Packet("R837", 0), 0));
        await other.EvaluateAsync(At(Packet("R837", 1), 2));
        var wrongIp = Packet("R837", 2); wrongIp.Destination = "1.1.1.1";
        Assert.False((await other.EvaluateAsync(At(wrongIp, 4))).Matched);
    }

    [Fact]
    public async Task TemporalDnsChurnDiffersFromMultiAnswerSinglePacket()
    {
        var rule = Rule("R844");
        for (var i = 0; i < 6; i++)
        {
            var response = Packet("R844", i % 3);
            response.DnsAnswers = "1.1.1.1, 1.0.0.1, 9.9.9.9, 8.8.4.4";
            Assert.False((await rule.EvaluateAsync(At(response, i * 2))).Matched);
        }
    }

    [Fact]
    public async Task ReverseDirectionIsMandatoryForApiResponse()
    {
        var rule = Rule("R842");
        await rule.EvaluateAsync(At(Packet("R842", 0), 0));
        var outgoingAgain = Packet("R842", 0);
        Assert.False((await rule.EvaluateAsync(At(outgoingAgain, 2))).Matched);
    }

    [Fact]
    public async Task OtherPeerAndSubnetAreRequiredForScpFanout()
    {
        var rule = Rule("R845");
        await rule.EvaluateAsync(At(Packet("R845", 0), 0));
        var samePeer = Packet("R845", 1); samePeer.Destination = "10.2.1.11";
        Assert.False((await rule.EvaluateAsync(At(samePeer, 2))).Matched);
    }

    [Fact]
    public void RegistryHasUniqueCandidateShadowRules()
    {
        var rules = RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count, rules.Select(r => r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var id in Ids)
        {
            var rule = Assert.Single(rules.Where(r => r.Descriptor.RuleId == id));
            var precision = Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(rule).PrecisionProfile;
            Assert.Equal(RulePrecisionMaturity.Candidate, precision.Maturity);
            Assert.Equal(RuleRuntimeMode.Shadow, precision.DefaultMode);
        }
    }

    public static TheoryData<string> Cases => new()
    { "R836", "R837", "R838", "R839", "R840", "R841", "R842", "R843", "R844", "R845" };
}
