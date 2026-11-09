// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Tests authored first; 0 executed at owner request.
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

public sealed class R806R815IndependentTelemetryCandidatesTests
{
    private static readonly DateTime Epoch = new(2026, 11, 9, 0, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids = { "R806", "R807", "R808", "R809", "R810", "R811", "R812", "R813", "R814", "R815" };

    private static IDetectionRule Rule(string id) => id switch
    {
        "R806" => new R806_DockerManifestThenMinerPoolPayloadRule(),
        "R807" => new R807_PublicSshServiceThenEastWestSshRule(),
        "R808" => new R808_LdapmodifyKerberosThenLdapSynRule(),
        "R809" => new R809_PublicLoginThenPortalAdminPostRule(),
        "R810" => new R810_FrpcQuicPublicPeerFanoutRule(),
        "R811" => new R811_ExpiredCertificateUnusualTlsPortRule(),
        "R812" => new R812_OpensslPublicUdpPayloadBurstRule(),
        "R813" => new R813_PowershellPublicApiPathEnumerationRule(),
        "R814" => new R814_PowershellMediaGetThenUnusualTlsEgressRule(),
        "R815" => new R815_OsascriptAlternatingTlsPayloadSizesRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static int Threshold(string id) => id switch
    {
        "R810" => 3,
        "R812" or "R813" or "R815" => 4,
        _ => 2
    };
    private static int Spacing(string id) => id == "R815" ? 10 : 3;

    private static TrafficRecord Packet(string id, int stage)
    {
        var r = new TrafficRecord
        {
            Id = Guid.NewGuid(), IpVersion = 4, Source = "10.1.1.10", Destination = "8.8.8.8",
            Protocol = "TCP", IsTcp = true, IsUdp = false, SourcePort = 51000,
            DestinationPort = 443, TcpFlags = 0x02, L4Len = 0, Length = 40,
            ProcessName = "powershell.exe", ProcessId = 880,
            Info = "PRIVATE-RAW-EVIDENCE-MARKER"
        };
        switch (id)
        {
            case "R806":
                if (stage == 0)
                {
                    r.ProcessName = "docker"; r.DestinationPort = 80;
                    Http(r, "GET", "/v2/base/manifests/latest");
                }
                else
                {
                    r.ProcessName = "xmrig"; r.Destination = "9.9.9.9";
                    r.DestinationPort = 3333;
                    r.TcpFlags = 0x18; r.L4Len = 600; r.Length = 640;
                }
                break;
            case "R807":
                if (stage == 0)
                {
                    r.SourcePort = 22; r.DestinationPort = 52000; r.TcpFlags = 0x12;
                    r.ProcessName = "sshd";
                }
                else
                {
                    r.Destination = "10.1.2.20"; r.DestinationPort = 22;
                    r.ProcessName = "ssh";
                }
                break;
            case "R808":
                r.ProcessName = "ldapmodify"; r.Destination = "10.1.2.20";
                r.DestinationPort = stage == 0 ? 88 : 389;
                break;
            case "R809":
                r.Source = "8.8.8.8"; r.Destination = "10.1.1.10";
                r.DestinationPort = 80; Http(r, "POST", stage == 0 ? "/admin/login" : "/admin/theme");
                break;
            case "R810":
                r.ProcessName = "frpc"; r.Destination = "9.9.9." + (1 + stage);
                Udp(r, 443, 120); r.IsQuic = true; r.QuicVersion = "0x00000001";
                break;
            case "R811":
                r.Source = "8.8.8.8"; r.Destination = "10.1.1.10";
                r.SourcePort = 9443; r.DestinationPort = 53000 + stage;
                r.TcpFlags = 0x18; r.L4Len = 512; r.Length = 552;
                r.TlsVersion = "TLS1.2"; r.CertIssuer = "Test Authority";
                r.CertSubject = "remote.example.org"; r.CertValidTo = Epoch.AddDays(-32);
                break;
            case "R812":
                r.ProcessName = "openssl"; Udp(r, 4444, 620);
                break;
            case "R813":
                r.DestinationPort = 80;
                Http(r, "GET", "/api/v1/resource/" + (stage + 1));
                break;
            case "R814":
                if (stage == 0)
                {
                    r.DestinationPort = 80; Http(r, "GET", "/images/banner.png");
                }
                else
                {
                    r.Destination = "9.9.9.9"; r.DestinationPort = 8443;
                    r.TcpFlags = 0x18; r.L4Len = 1800; r.Length = 1840;
                    r.TlsVersion = "TLS1.3"; r.Sni = "relay.example.org";
                }
                break;
            case "R815":
                r.ProcessName = "osascript"; r.TcpFlags = 0x18;
                r.L4Len = stage switch { 0 => 180, 1 => 1300, 2 => 190, _ => 1400 };
                r.Length = r.L4Len.Value + 40; r.TlsVersion = "TLS1.3";
                r.Sni = "edge.example.org";
                break;
        }
        return r;
    }

    private static void Udp(TrafficRecord r, int port, int bytes)
    {
        r.Protocol = "UDP"; r.IsTcp = false; r.IsUdp = true;
        r.TcpFlags = null; r.DestinationPort = port;
        r.L4Len = bytes; r.Length = bytes + 28;
    }

    private static void Http(TrafficRecord r, string method, string uri)
    {
        r.TcpFlags = 0x18; r.L4Len = 340; r.Length = 380;
        r.ApplicationProtocol = "HTTP"; r.HttpMethod = method;
        r.HttpUri = uri; r.HttpHost = "telemetry.example.org";
    }

    private static RuleEvaluationContext At(TrafficRecord r, double seconds)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, double start)
    {
        RuleEvaluationResult? result = null;
        for (var i = 0; i < Threshold(id); i++)
            result = await rule.EvaluateAsync(At(Packet(id, i), start + i * Spacing(id)));
        return result!;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task CompleteTypedSequenceMatchesButMissingOrContradictoryTransportDoesNot(string id)
    {
        Assert.True((await Trigger(Rule(id), id, 0)).Matched);
        var invalid = Rule(id);
        var missing = Rule(id);
        for (var i = 0; i < Threshold(id); i++)
        {
            var contradictory = Packet(id, i); contradictory.IsTcp = true; contradictory.IsUdp = true;
            Assert.False((await invalid.EvaluateAsync(At(contradictory, 3 * i))).Matched);
            var absent = Packet(id, i); absent.Destination = null;
            Assert.False((await missing.EvaluateAsync(At(absent, 3 * i))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task AuthorizedLookingNearMissWithoutSpecificDiscriminatorNeverMatches(string id)
    {
        var rule = Rule(id);
        for (var i = 0; i < Threshold(id) + 2; i++)
        {
            var r = Packet(id, i % Threshold(id));
            switch (id)
            {
                case "R806": r.ProcessName = "browser.exe"; break;
                case "R807": r.ProcessName = "browser.exe"; break;
                case "R808": r.ProcessName = "browser.exe"; break;
                case "R809": r.HttpUri = "/api/health"; break;
                case "R810": r.ProcessName = "browser.exe"; break;
                case "R811": r.CertValidTo = Epoch.AddDays(60); break;
                case "R812": r.ProcessName = "browser.exe"; break;
                case "R813": r.HttpUri = "/api/health"; break;
                case "R814": r.ProcessName = "browser.exe"; break;
                case "R815": r.ProcessName = "browser.exe"; break;
            }
            Assert.False((await rule.EvaluateAsync(At(r, i * Spacing(id)))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task DuplicatePacketIdReversedTimeAndExpiredWindowFailClosed(string id)
    {
        var rule = Rule(id);
        var first = Packet(id, 0);
        await rule.EvaluateAsync(At(first, 10));
        for (var i = 1; i < Threshold(id); i++)
        {
            var replay = Packet(id, i); replay.Id = first.Id;
            Assert.False((await rule.EvaluateAsync(At(replay, 10 + i * Spacing(id)))).Matched);
        }
        Assert.False((await rule.EvaluateAsync(At(Packet(id, Threshold(id) - 1), 9))).Matched);
        var expired = Rule(id);
        await expired.EvaluateAsync(At(Packet(id, 0), 0));
        for (var i = 1; i < Threshold(id); i++)
            Assert.False((await expired.EvaluateAsync(At(Packet(id, i), 250 + i * Spacing(id)))).Matched);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task CooldownRecoversWithoutRawEvidenceLeak(string id)
    {
        var rule = Rule(id);
        var first = await Trigger(rule, id, 0);
        Assert.True(first.Matched);
        var json = JsonSerializer.Serialize(first.Events);
        Assert.DoesNotContain("PRIVATE-RAW-EVIDENCE-MARKER", json);
        Assert.True((await Trigger(rule, id, 300)).Suppressed);
        Assert.True((await Trigger(rule, id, 940)).Matched);
    }

    [Fact]
    public async Task MediaGetMustUseDifferentPublicPeerForTlsFollowUp()
    {
        var rule = Rule("R814");
        await rule.EvaluateAsync(At(Packet("R814", 0), 0));
        var samePeer = Packet("R814", 1); samePeer.Destination = "8.8.8.8";
        Assert.False((await rule.EvaluateAsync(At(samePeer, 3))).Matched);
    }

    [Fact]
    public async Task FixedSizePacketsDoNotMeetAlternationPredicate()
    {
        var rule = Rule("R815");
        for (var i = 0; i < 6; i++)
        {
            var packet = Packet("R815", 0);
            Assert.False((await rule.EvaluateAsync(At(packet, i * 10))).Matched);
        }
    }

    [Fact]
    public async Task CertificateExpiryNeedsMetadataButNotSeparateTlsVersionField()
    {
        var rule = Rule("R811");
        var first = Packet("R811", 0); first.TlsVersion = null;
        var second = Packet("R811", 1); second.TlsVersion = null;
        Assert.False((await rule.EvaluateAsync(At(first, 0))).Matched);
        Assert.True((await rule.EvaluateAsync(At(second, 3))).Matched);
    }

    [Fact]
    public async Task QuicCandidateRejectsMissingPayloadLengthWithoutThrowing()
    {
        var packet = Packet("R810", 0);
        packet.L4Len = null;
        Assert.False((await Rule("R810").EvaluateAsync(At(packet, 0))).Matched);
    }

    [Fact]
    public async Task AdjacentCandidatePredicatesStayIndependent()
    {
        for (var i = 0; i < Ids.Length; i++)
        {
            var rule = Rule(Ids[i]);
            var other = Ids[(i + 1) % Ids.Length];
            for (var stage = 0; stage < Threshold(other) + 2; stage++)
                Assert.False((await rule.EvaluateAsync(At(
                    Packet(other, stage % Threshold(other)), stage * Spacing(other)))).Matched);
        }
    }

    [Fact]
    public void RegistryHasOneOfEveryCandidateShadowRule()
    {
        var rules = RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count, rules.Select(r => r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var id in Ids)
        {
            var candidate = Assert.Single(rules.Where(r => r.Descriptor.RuleId == id));
            var precision = Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(candidate);
            Assert.Equal(RulePrecisionMaturity.Candidate, precision.PrecisionProfile.Maturity);
            Assert.Equal(RuleRuntimeMode.Shadow, precision.PrecisionProfile.DefaultMode);
        }
    }

    public static TheoryData<string> Cases => new()
    { "R806", "R807", "R808", "R809", "R810", "R811", "R812", "R813", "R814", "R815" };
}
