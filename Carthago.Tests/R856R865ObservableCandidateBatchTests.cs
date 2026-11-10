// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Test source authored first; no tests/builds executed.
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

public sealed class R856R865ObservableCandidateBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 10, 0, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids =
        { "R856", "R857", "R858", "R859", "R860", "R861", "R862", "R863", "R864", "R865" };

    private static IDetectionRule Rule(string id) => id switch
    {
        "R856" => new R856_FrpcPublicTcp7000SynThenPayloadRule(),
        "R857" => new R857_AwkUnusualPublicTlsPayloadRule(),
        "R858" => new R858_HostdPublicTls9443BurstRule(),
        "R859" => new R859_PublicSshIngressThenEsxcliPublicTlsRule(),
        "R860" => new R860_Regsvr32PublicUdp1194FanoutRule(),
        "R861" => new R861_ThunderbirdZipGetThenBashTlsRule(),
        "R862" => new R862_Rundll32DnsTxtThenSameNameTlsRule(),
        "R863" => new R863_RsyncPublic873PayloadBurstRule(),
        "R864" => new R864_DockerProxyPublicSocksSynFanoutRule(),
        "R865" => new R865_CurlCmdGetThenCmdPublicSynRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static int Threshold(string id) => id switch
    {
        "R857" => 1,
        "R858" or "R863" => 5,
        "R860" or "R864" => 3,
        _ => 2
    };

    private static TrafficRecord Packet(string id, int stage)
    {
        var r = new TrafficRecord
        {
            Id = Guid.NewGuid(), IpVersion = 4, Source = "10.1.1.10", Destination = "8.8.8.8",
            Protocol = "TCP", IsTcp = true, SourcePort = 51000, DestinationPort = 8443,
            TcpFlags = 0x02, L4Len = 0, Length = 40, ProcessName = "frpc.exe", ProcessId = 312,
            Info = "PRIVATE-RAW-EVIDENCE-MARKER"
        };
        switch (id)
        {
            case "R856":
                r.DestinationPort = 7000;
                if (stage == 1) Data(r, 700);
                break;
            case "R857":
                r.ProcessName = "awk"; Tls(r, 8443, "relay.example.net", 750);
                break;
            case "R858":
                r.ProcessName = "hostd"; Tls(r, 9443, "backup.example.net", 1900);
                break;
            case "R859":
                if (stage == 0)
                {
                    Syn(r, "8.8.8.8", "10.1.1.10", 54000, 22);
                    r.ProcessId = 0; r.ProcessName = null;
                }
                else
                {
                    r.ProcessName = "esxcli"; r.Destination = "9.9.9.9";
                    Tls(r, 8443, "management.example.net", 650);
                }
                break;
            case "R860":
                r.ProcessName = "regsvr32.exe"; r.Destination = "9.9.9." + (stage + 1);
                Udp(r, 1194, 900);
                break;
            case "R861":
                if (stage == 0)
                {
                    r.ProcessName = "thunderbird.exe";
                    HttpGet(r, "/downloads/attachment.zip", "mail.example.net");
                }
                else
                {
                    r.ProcessName = "bash"; r.Destination = "9.9.9.9";
                    Tls(r, 8443, "relay.example.net", 750);
                }
                break;
            case "R862":
                r.ProcessName = "rundll32.exe";
                if (stage == 0)
                {
                    Udp(r, 53, 160); r.DnsQname = "relay.example.net"; r.DnsQtype = "TXT";
                    r.ApplicationProtocol = "DNS";
                }
                else
                {
                    r.Destination = "9.9.9.9"; Tls(r, 443, "relay.example.net", 700);
                }
                break;
            case "R863":
                r.ProcessName = "rsync"; r.DestinationPort = 873;
                Data(r, 2200);
                break;
            case "R864":
                r.ProcessName = "docker-proxy"; r.DestinationPort = 1080;
                r.Destination = "9.9.9." + (stage + 1);
                break;
            case "R865":
                if (stage == 0)
                {
                    r.ProcessName = "curl.exe";
                    HttpGet(r, "/bin/update.cmd", "downloads.example.net");
                }
                else
                {
                    r.ProcessName = "cmd.exe"; r.Destination = "9.9.9.9";
                    r.DestinationPort = 8443;
                }
                break;
        }
        return r;
    }

    private static void Syn(TrafficRecord r, string source, string destination, int sourcePort, int destinationPort)
    {
        r.Source = source; r.Destination = destination;
        r.SourcePort = sourcePort; r.DestinationPort = destinationPort;
        r.TcpFlags = 0x02; r.L4Len = 0; r.Length = 40;
        r.TlsVersion = r.Sni = r.HttpMethod = r.HttpUri = r.ApplicationProtocol = null;
    }

    private static void Data(TrafficRecord r, int size)
    {
        r.TcpFlags = 0x18; r.L4Len = size; r.Length = size + 40;
    }

    private static void Tls(TrafficRecord r, int port, string sni, int size)
    {
        Data(r, size); r.DestinationPort = port; r.TlsVersion = "TLS1.3"; r.Sni = sni;
        r.HttpMethod = r.HttpUri = r.ApplicationProtocol = null;
    }

    private static void Udp(TrafficRecord r, int destPort, int size)
    {
        r.Protocol = "UDP"; r.IsTcp = false; r.IsUdp = true;
        r.TcpFlags = null; r.DestinationPort = destPort;
        r.L4Len = size; r.Length = size + 28;
    }

    private static void HttpGet(TrafficRecord r, string uri, string host)
    {
        Data(r, 440); r.DestinationPort = 80;
        r.ApplicationProtocol = "HTTP"; r.HttpMethod = "GET"; r.HttpUri = uri; r.HttpHost = host;
    }

    private static RuleEvaluationContext At(TrafficRecord record, double seconds)
        => new(record, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, double start)
    {
        RuleEvaluationResult? result = null;
        for (var i = 0; i < Threshold(id); i++)
            result = await rule.EvaluateAsync(At(Packet(id, i), start + 3 * i));
        return result!;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task PositiveTypedCaseMatchesButPrivateInfoDoesNotLeak(string id)
    {
        var result = await Trigger(Rule(id), id, 0);
        Assert.True(result.Matched);
        Assert.DoesNotContain("PRIVATE-RAW-EVIDENCE-MARKER", JsonSerializer.Serialize(result.Events));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task MissingDestinationAndContradictoryTcpUdpFailClosed(string id)
    {
        var missing = Rule(id); var contradictory = Rule(id);
        for (var i = 0; i < Threshold(id); i++)
        {
            var noPeer = Packet(id, i); noPeer.Destination = null;
            Assert.False((await missing.EvaluateAsync(At(noPeer, i * 3))).Matched);
            var dual = Packet(id, i); dual.IsUdp = dual.IsTcp = true;
            Assert.False((await contradictory.EvaluateAsync(At(dual, i * 3))).Matched);
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
                case "R856": r.ProcessName = "explorer.exe"; break;
                case "R857": r.ProcessName = "explorer.exe"; break;
                case "R858": r.Sni = null; break;
                case "R859": r.DestinationPort = 2222; r.ProcessName = "explorer.exe"; break;
                case "R860": r.Destination = "9.9.9.1"; break;
                case "R861": r.HttpUri = "/downloads/attachment.txt"; r.TlsVersion = null; break;
                case "R862": r.DnsQtype = "A"; r.Sni = "other.example.net"; break;
                case "R863": r.ProcessName = "explorer.exe"; break;
                case "R864": r.ProcessName = "explorer.exe"; break;
                case "R865": r.HttpUri = "/bin/update.txt"; r.ProcessName = "explorer.exe"; break;
            }
            Assert.False((await rule.EvaluateAsync(At(r, i * 3))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task DuplicatePacketAndExpiredFirstStageDoNotComplete(string id)
    {
        var repeated = Rule(id); var first = Packet(id, 0);
        await repeated.EvaluateAsync(At(first, 0));
        for (var i = 1; i < Threshold(id); i++)
        {
            var duplicate = Packet(id, i); duplicate.Id = first.Id;
            Assert.False((await repeated.EvaluateAsync(At(duplicate, i * 3))).Matched);
        }
        if (Threshold(id) == 1) return;
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
    public async Task TxtQueryAndTlsSniMustBeSameNameAndProcess()
    {
        var rule = Rule("R862");
        await rule.EvaluateAsync(At(Packet("R862", 0), 0));
        var changed = Packet("R862", 1); changed.Sni = "other.example.net";
        Assert.False((await rule.EvaluateAsync(At(changed, 3))).Matched);
        var otherPid = Packet("R862", 1); otherPid.ProcessId = 999;
        Assert.False((await rule.EvaluateAsync(At(otherPid, 6))).Matched);
    }

    [Fact]
    public async Task FrpcSecondStageMustKeepSamePeer()
    {
        var rule = Rule("R856");
        await rule.EvaluateAsync(At(Packet("R856", 0), 0));
        var otherPeer = Packet("R856", 1); otherPeer.Destination = "9.9.9.9";
        Assert.False((await rule.EvaluateAsync(At(otherPeer, 3))).Matched);
    }

    [Fact]
    public async Task AllNeighboringRulePredicatesAreIndependent()
    {
        for (var i = 0; i < Ids.Length; i++)
        {
            var rule = Rule(Ids[i]); var next = Ids[(i + 1) % Ids.Length];
            for (var j = 0; j < Threshold(next) + 2; j++)
                Assert.False((await rule.EvaluateAsync(At(Packet(next, j % Threshold(next)), j * 3))).Matched);
        }
    }

    [Fact]
    public void RegistryContainsUniqueCandidateShadowInstances()
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
    { "R856", "R857", "R858", "R859", "R860", "R861", "R862", "R863", "R864", "R865" };
}
