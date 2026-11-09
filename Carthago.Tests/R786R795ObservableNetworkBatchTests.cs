// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit source authored, 0 tests executed.
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

public sealed class R786R795ObservableNetworkBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 9, 0, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids = { "R786", "R787", "R788", "R789", "R790", "R791", "R792", "R793", "R794", "R795" };

    private static IDetectionRule Rule(string id) => id switch
    {
        "R786" => new R786_TcpDnsTxtLargeQueryBurstRule(),
        "R787" => new R787_DnsThenUnusualPublicConnectRule(),
        "R788" => new R788_DnsResolverMultiUpstreamTxtQueryRule(),
        "R789" => new R789_NetProcessSmbWriteThenFinRule(),
        "R790" => new R790_RemoteTlsIssuerShiftRule(),
        "R791" => new R791_PublicAdminPostThenCurlEgressRule(),
        "R792" => new R792_EsxiFtpThenTftpEgressRule(),
        "R793" => new R793_PublicProxyIngressThenNginxEgressRule(),
        "R794" => new R794_InterSubnetRelayToAdminPortRule(),
        "R795" => new R795_PublicManagementUploadPostBurstRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static int Threshold(string id) => id switch { "R786" or "R795" => 4, "R788" => 3, _ => 2 };

    private static TrafficRecord Packet(string id, int step)
    {
        var r = new TrafficRecord
        {
            Id = Guid.NewGuid(), IpVersion = 4, Source = "10.1.1.10", Destination = "8.8.8.8",
            Protocol = "TCP", IsTcp = true, SourcePort = 51000, DestinationPort = 443,
            TcpFlags = 0x18, L4Len = 700, Length = 740,
            ProcessName = "powershell.exe", ProcessId = 880,
            Info = "PRIVATE-RAW-PAYLOAD-MARKER"
        };
        switch (id)
        {
            case "R786":
                r.DestinationPort = 53; r.ApplicationProtocol = "DNS";
                r.DnsQname = "a.example.net"; r.DnsQtype = "TXT";
                break;
            case "R787":
                if (step == 0)
                {
                    r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP"; r.TcpFlags = null;
                    r.DestinationPort = 53; r.ApplicationProtocol = "DNS";
                    r.DnsQname = "remote.example.net"; r.DnsQtype = "A";
                    r.L4Len = 100; r.Length = 128;
                }
                else { r.Destination = "9.9.9.9"; r.DestinationPort = 49211; r.TcpFlags = 0x02; r.L4Len = 0; r.Length = 40; }
                break;
            case "R788":
                r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP"; r.TcpFlags = null;
                r.DestinationPort = 53; r.ApplicationProtocol = "DNS";
                r.DnsQname = "business.example.net"; r.DnsQtype = "TXT";
                r.ProcessName = "named"; r.Destination = step switch { 0 => "8.8.8.8", 1 => "9.9.9.9", _ => "1.1.1.1" };
                r.L4Len = 130; r.Length = 158;
                break;
            case "R789":
                r.Destination = "10.1.2.20"; r.DestinationPort = 445; r.ProcessName = "net.exe";
                if (step == 0) r.ApplicationProtocol = "smb2.write.request";
                else { r.TcpFlags = 0x11; r.L4Len = 0; r.Length = 40; }
                break;
            case "R790":
                r.Source = "8.8.8.8"; r.Destination = "10.1.1.10";
                r.SourcePort = 443; r.DestinationPort = 51000;
                r.CertIssuer = step == 0 ? "CN=Trusted Issuer A" : "CN=Trusted Issuer B";
                r.CertSubject = "CN=remote.example.net"; r.TlsVersion = null;
                break;
            case "R791":
                if (step == 0)
                {
                    r.Source = "8.8.8.8"; r.Destination = "10.1.1.10";
                    r.DestinationPort = 8080; r.ApplicationProtocol = "HTTP";
                    r.HttpMethod = "POST"; r.HttpUri = "/admin/api";
                }
                else { r.Destination = "1.1.1.1"; r.ProcessName = "curl"; r.TlsVersion = "TLS1.2"; r.Sni = "example.net"; }
                break;
            case "R792":
                r.ProcessName = "hostd";
                if (step == 0)
                {
                    r.DestinationPort = 21; r.ApplicationProtocol = "ftp.stor";
                    r.L4Len = 80; r.Length = 120;
                }
                else
                {
                    r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP"; r.TcpFlags = null;
                    r.DestinationPort = 69; r.L4Len = 512; r.Length = 540;
                }
                break;
            case "R793":
                if (step == 0)
                {
                    r.Source = "8.8.8.8"; r.Destination = "10.1.1.10";
                    r.DestinationPort = 3128; r.TcpFlags = 0x02; r.L4Len = 0; r.Length = 40;
                }
                else
                {
                    r.Destination = "9.9.9.9"; r.DestinationPort = 8443;
                    r.TcpFlags = 0x02; r.L4Len = 0; r.Length = 40; r.ProcessName = "nginx";
                }
                break;
            case "R794":
                if (step == 0)
                {
                    r.Source = "10.1.1.20"; r.Destination = "10.1.2.10";
                    r.DestinationPort = 1080; r.TcpFlags = 0x02; r.L4Len = 0; r.Length = 40;
                }
                else
                {
                    r.Source = "10.1.2.10"; r.Destination = "10.1.3.20";
                    r.DestinationPort = 3389; r.TcpFlags = 0x02; r.L4Len = 0; r.Length = 40;
                }
                break;
            case "R795":
                r.Source = "8.8.8.8"; r.Destination = "10.1.1.10";
                r.DestinationPort = 8080; r.ApplicationProtocol = "HTTP";
                r.HttpMethod = "POST"; r.HttpUri = "/system/firmware/upload";
                r.L4Len = 3000; r.Length = 3040;
                break;
        }
        return r;
    }

    private static RuleEvaluationContext At(TrafficRecord packet, double offset)
        => new(packet, Sensitivity.Balanced, Epoch.AddSeconds(offset));

    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, double offset)
    {
        RuleEvaluationResult? last = null;
        for (var i = 0; i < Threshold(id); i++)
            last = await rule.EvaluateAsync(At(Packet(id, i), offset + i * 3));
        return last!;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task PositiveAndContradictoryTelemetryFailClosed(string id)
    {
        Assert.True((await Trigger(Rule(id), id, 0)).Matched);
        var wrongTransport = Rule(id);
        for (var i = 0; i < Threshold(id); i++)
        {
            var packet = Packet(id, i);
            packet.IsTcp = true; packet.IsUdp = true;
            Assert.False((await wrongTransport.EvaluateAsync(At(packet, i * 3))).Matched);
        }
        var missingEndpoints = Rule(id);
        for (var i = 0; i < Threshold(id); i++)
        {
            var packet = Packet(id, i); packet.Source = null;
            Assert.False((await missingEndpoints.EvaluateAsync(At(packet, i * 3))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task BenignNearMissForEveryIndependentPredicate(string id)
    {
        var rule = Rule(id);
        for (var i = 0; i < Threshold(id) + 2; i++)
        {
            var packet = Packet(id, i % Threshold(id));
            switch (id)
            {
                case "R786": packet.DnsQtype = "A"; break;
                case "R787": packet.ProcessName = "browser.exe"; break;
                case "R788": packet.Destination = "8.8.8.8"; break;
                case "R789": packet.ProcessName = "explorer.exe"; break;
                case "R790": packet.CertIssuer = "CN=Trusted Issuer A"; break;
                case "R791": packet.DestinationPort = 80; break;
                case "R792": packet.ProcessName = "browser"; break;
                case "R793": packet.DestinationPort = 443; break;
                case "R794": packet.Destination = "10.1.2.20"; break;
                case "R795": packet.HttpMethod = "GET"; break;
            }
            Assert.False((await rule.EvaluateAsync(At(packet, i * 3))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task ReplayedAndOutOfOrderPacketsDoNotCompleteWindows(string id)
    {
        var rule = Rule(id);
        var first = Packet(id, 0);
        await rule.EvaluateAsync(At(first, 10));
        for (var i = 1; i < Threshold(id); i++)
        {
            var dup = Packet(id, i); dup.Id = first.Id;
            Assert.False((await rule.EvaluateAsync(At(dup, 10 + i * 3))).Matched);
        }
        var reversed = Packet(id, Threshold(id) - 1);
        Assert.False((await rule.EvaluateAsync(At(reversed, 9))).Matched);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task ExpiryCooldownAndEvidencePrivacy(string id)
    {
        var expired = Rule(id);
        await expired.EvaluateAsync(At(Packet(id, 0), 0));
        for (var i = 1; i < Threshold(id); i++)
            Assert.False((await expired.EvaluateAsync(At(Packet(id, i), 240 + i * 3))).Matched);

        var rule = Rule(id);
        var first = await Trigger(rule, id, 0);
        Assert.True(first.Matched);
        var serialized = JsonSerializer.Serialize(first.Events);
        Assert.DoesNotContain("PRIVATE-RAW-PAYLOAD-MARKER", serialized);
        Assert.DoesNotContain("business.example.net", serialized);
        Assert.True((await Trigger(rule, id, 300)).Suppressed);
        Assert.True((await Trigger(rule, id, 920)).Matched);
    }

    [Fact]
    public async Task DifferentPredicatesRemainIndependent()
    {
        foreach (var id in Ids)
        {
            var next = Ids[(Array.IndexOf(Ids, id) + 1) % Ids.Length];
            var rule = Rule(id);
            for (var i = 0; i < 5; i++)
                Assert.False((await rule.EvaluateAsync(At(Packet(next, i % Threshold(next)), i * 3))).Matched);
        }
    }

    [Fact]
    public void RegistryIdsAndCandidateShadowProfilesAreUnique()
    {
        var rules = RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count, rules.Select(r => r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var id in Ids)
        {
            var rule = Assert.Single(rules.Where(r => r.Descriptor.RuleId == id));
            var precision = Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(rule);
            Assert.Equal(RulePrecisionMaturity.Candidate, precision.PrecisionProfile.Maturity);
            Assert.Equal(RuleRuntimeMode.Shadow, precision.PrecisionProfile.DefaultMode);
        }
    }

    public static TheoryData<string> Cases => new() { "R786", "R787", "R788", "R789", "R790", "R791", "R792", "R793", "R794", "R795" };
}
