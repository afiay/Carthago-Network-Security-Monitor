// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Authored before implementation; no tests executed by owner request.
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

public sealed class R816R825ObservableCandidateBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 9, 0, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids = { "R816", "R817", "R818", "R819", "R820", "R821", "R822", "R823", "R824", "R825" };

    private static IDetectionRule Rule(string id) => id switch
    {
        "R816" => new R816_ConfluenceApiDistinctPageGetRule(),
        "R817" => new R817_ScriptHttpGetThenShellPublicEgressRule(),
        "R818" => new R818_IdeMarketplaceThenUnusualTlsPortRule(),
        "R819" => new R819_PublicConfigExportGetThenTftpEgressRule(),
        "R820" => new R820_SafariJavascriptThenOsascriptTlsRule(),
        "R821" => new R821_DockerContainerThenImageApiEnumerationRule(),
        "R822" => new R822_DockerBuildPostThenExternalSynRule(),
        "R823" => new R823_DsclLdapThenLdapsSynRule(),
        "R824" => new R824_PingProcessPublicIcmpTargetFanoutRule(),
        "R825" => new R825_PublicWebUploadThenServedGetRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static int Threshold(string id) => id switch { "R816" => 4, "R824" => 3, _ => 2 };

    private static TrafficRecord Packet(string id, int stage)
    {
        var r = new TrafficRecord
        {
            Id = Guid.NewGuid(), IpVersion = 4,
            Source = "10.1.1.10", Destination = "8.8.8.8",
            Protocol = "TCP", IsTcp = true, IsUdp = false,
            SourcePort = 51000, DestinationPort = 443, TcpFlags = 0x02,
            L4Len = 0, Length = 40, ProcessName = "curl", ProcessId = 840,
            Info = "PRIVATE-RAW-EVIDENCE-MARKER"
        };
        switch (id)
        {
            case "R816":
                r.DestinationPort = 80;
                Http(r, "GET", "/rest/api/content/" + (stage + 1), "confluence.example.org");
                break;
            case "R817":
                if (stage == 0) { r.DestinationPort = 80; Http(r, "GET", "/scripts/update.sh"); }
                else
                {
                    r.ProcessName = "bash"; r.Destination = "9.9.9.9";
                    TlsData(r, 8443, 512, "relay.example.org");
                }
                break;
            case "R818":
                r.ProcessName = "code";
                if (stage == 0) TlsData(r, 443, 440, "marketplace.visualstudio.com");
                else { r.Destination = "9.9.9.9"; r.DestinationPort = 8443; }
                break;
            case "R819":
                if (stage == 0)
                {
                    r.Source = "8.8.8.8"; r.Destination = "10.1.1.10";
                    r.DestinationPort = 80; Http(r, "GET", "/api/config/export", "device.example.org");
                }
                else { r = TftpCaptureQualificationTests.Initial("10.1.1.10", "9.9.9.9", 2); r.Info = "PRIVATE-RAW-EVIDENCE-MARKER"; }
                break;
            case "R820":
                if (stage == 0)
                {
                    r.ProcessName = "safari"; r.DestinationPort = 80;
                    Http(r, "GET", "/js/update.js");
                }
                else
                {
                    r.ProcessName = "osascript"; r.Destination = "9.9.9.9";
                    TlsData(r, 8443, 600, "relay.example.org");
                }
                break;
            case "R821":
                r.ProcessName = "docker"; r.Destination = "10.1.2.20"; r.DestinationPort = 2375;
                Http(r, "GET", stage == 0 ? "/containers/json" : "/images/json", "docker.local");
                break;
            case "R822":
                r.ProcessName = "docker";
                if (stage == 0)
                {
                    r.Destination = "10.1.2.20"; r.DestinationPort = 2375;
                    Http(r, "POST", "/build", "docker.local");
                }
                break;
            case "R823":
                r.ProcessName = "dscl"; r.Destination = "10.1.2.20";
                r.DestinationPort = stage == 0 ? 389 : 636;
                break;
            case "R824":
                r.ProcessName = "ping"; r.Destination = "9.9.9." + (1 + stage);
                r.Protocol = "ICMP"; r.IsTcp = false; r.IsUdp = false;
                r.SourcePort = null; r.DestinationPort = null; r.TcpFlags = null;
                r.IcmpTypeCode = 0x0800; r.L4Len = 20; r.Length = 48;
                break;
            case "R825":
                r.Source = "8.8.8.8"; r.Destination = "10.1.1.10";
                r.DestinationPort = 80;
                Http(r, stage == 0 ? "POST" : "GET",
                    stage == 0 ? "/upload/banner.png" : "/uploads/banner.png", "portal.example.org");
                break;
        }
        return r;
    }

    private static void Http(TrafficRecord r, string method, string uri, string host = "updates.example.org")
    {
        r.TcpFlags = 0x18; r.L4Len = 440; r.Length = 480;
        r.ApplicationProtocol = "HTTP"; r.HttpMethod = method; r.HttpUri = uri; r.HttpHost = host;
    }

    private static void TlsData(TrafficRecord r, int port, int size, string host)
    {
        r.DestinationPort = port; r.TcpFlags = 0x18;
        r.L4Len = size; r.Length = size + 40; r.TlsVersion = "TLS1.3"; r.Sni = host;
    }

    private static void Udp(TrafficRecord r, int port, int size)
    {
        r.Protocol = "UDP"; r.IsTcp = false; r.IsUdp = true;
        r.DestinationPort = port; r.TcpFlags = null;
        r.L4Len = size; r.Length = size + 28;
    }

    private static RuleEvaluationContext At(TrafficRecord record, double seconds)
        => new(record, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, double at)
    {
        RuleEvaluationResult? last = null;
        for (var stage = 0; stage < Threshold(id); stage++)
            last = await rule.EvaluateAsync(At(Packet(id, stage), at + stage * 3));
        return last!;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task TypedEvidenceMatchesAndContradictoryOrMissingFieldsFail(string id)
    {
        Assert.True((await Trigger(Rule(id), id, 0)).Matched);
        var contradictory = Rule(id);
        var missing = Rule(id);
        for (var i = 0; i < Threshold(id); i++)
        {
            var badProtocol = Packet(id, i);
            badProtocol.IsTcp = true; badProtocol.IsUdp = true;
            Assert.False((await contradictory.EvaluateAsync(At(badProtocol, i * 3))).Matched);
            var missingPeer = Packet(id, i); missingPeer.Destination = null;
            Assert.False((await missing.EvaluateAsync(At(missingPeer, i * 3))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task BenignSubsetOrWrongLocalProcessNeverSatisfiesPredicate(string id)
    {
        var rule = Rule(id);
        for (var i = 0; i < Threshold(id) + 2; i++)
        {
            var r = Packet(id, i % Threshold(id));
            switch (id)
            {
                case "R819": r.HttpUri = "/api/health"; r.IsUdp = false; break;
                case "R816": r.HttpUri = "/rest/api/space"; break;
                case "R821": r.HttpUri = "/_ping"; break;
                case "R825": r.HttpUri = "/upload/unrelated.jpg"; break;
                default: r.ProcessName = "browser"; break;
            }
            Assert.False((await rule.EvaluateAsync(At(r, i * 3))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task DuplicateReverseTimeAndExpiredWindowFailClosed(string id)
    {
        var rule = Rule(id);
        var first = Packet(id, 0);
        await rule.EvaluateAsync(At(first, 10));
        for (var i = 1; i < Threshold(id); i++)
        {
            var replay = Packet(id, i); replay.Id = first.Id;
            Assert.False((await rule.EvaluateAsync(At(replay, 10 + i * 3))).Matched);
        }
        Assert.False((await rule.EvaluateAsync(At(Packet(id, Threshold(id) - 1), 9))).Matched);
        var expired = Rule(id);
        await expired.EvaluateAsync(At(Packet(id, 0), 0));
        for (var i = 1; i < Threshold(id); i++)
            Assert.False((await expired.EvaluateAsync(At(Packet(id, i), 250 + i * 3))).Matched);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task CooldownRecoveryAndNoRawInfoPropagation(string id)
    {
        var rule = Rule(id);
        var first = await Trigger(rule, id, 0);
        Assert.True(first.Matched);
        Assert.DoesNotContain("PRIVATE-RAW-EVIDENCE-MARKER", JsonSerializer.Serialize(first.Events));
        Assert.True((await Trigger(rule, id, 300)).Suppressed);
        Assert.True((await Trigger(rule, id, 940)).Matched);
    }

    [Fact]
    public async Task MatchingImageFilenameRequiredAcrossUploadAndGet()
    {
        var rule = Rule("R825");
        await rule.EvaluateAsync(At(Packet("R825", 0), 0));
        var wrongImage = Packet("R825", 1);
        wrongImage.HttpUri = "/uploads/another.png";
        Assert.False((await rule.EvaluateAsync(At(wrongImage, 3))).Matched);
    }

    [Fact]
    public async Task PublicIcmpTargetFanoutRequiresThreeDifferentPeers()
    {
        var rule = Rule("R824");
        for (var i = 0; i < 5; i++)
        {
            var r = Packet("R824", i % 3); r.Destination = "9.9.9.1";
            Assert.False((await rule.EvaluateAsync(At(r, i * 3))).Matched);
        }
    }

    [Fact]
    public async Task ConfigurationFollowUpFromUnrelatedHostNeverJoins()
    {
        var rule = Rule("R819");
        await rule.EvaluateAsync(At(Packet("R819", 0), 0));
        var unrelated = Packet("R819", 1); unrelated.Source = "10.1.3.30";
        Assert.False((await rule.EvaluateAsync(At(unrelated, 3))).Matched);
    }

    [Theory]
    [InlineData("R817")]
    [InlineData("R818")]
    [InlineData("R820")]
    public async Task TwoStageDifferentPeerSequencesRejectSamePeer(string id)
    {
        var rule = Rule(id);
        await rule.EvaluateAsync(At(Packet(id, 0), 0));
        var samePeer = Packet(id, 1); samePeer.Destination = "8.8.8.8";
        Assert.False((await rule.EvaluateAsync(At(samePeer, 3))).Matched);
    }

    [Fact]
    public async Task NeighboringPredicatesStayIndependent()
    {
        for (var i = 0; i < Ids.Length; i++)
        {
            var rule = Rule(Ids[i]);
            var neighbor = Ids[(i + 1) % Ids.Length];
            for (var stage = 0; stage < Threshold(neighbor) + 2; stage++)
                Assert.False((await rule.EvaluateAsync(At(
                    Packet(neighbor, stage % Threshold(neighbor)), stage * 3))).Matched);
        }
    }

    [Fact]
    public void RegistryContainsSingleCandidateShadowInstanceForEachId()
    {
        var rules = RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count, rules.Select(r => r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var id in Ids)
        {
            var candidate = Assert.Single(rules.Where(r => r.Descriptor.RuleId == id));
            var profile = Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(candidate).PrecisionProfile;
            Assert.Equal(RulePrecisionMaturity.Candidate, profile.Maturity);
            Assert.Equal(RuleRuntimeMode.Shadow, profile.DefaultMode);
        }
    }

    public static TheoryData<string> Cases => new()
    { "R816", "R817", "R818", "R819", "R820", "R821", "R822", "R823", "R824", "R825" };
}
