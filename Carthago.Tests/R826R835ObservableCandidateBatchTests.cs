// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Test source authored before implementation; never executed.
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

public sealed class R826R835ObservableCandidateBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 10, 0, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids = { "R826", "R827", "R828", "R829", "R830", "R831", "R832", "R833", "R834", "R835" };

    private static IDetectionRule Rule(string id) => id switch
    {
        "R826" => new R826_NotepadDistinctExternalSynRule(),
        "R827" => new R827_FingerPublicTargetFanoutRule(),
        "R828" => new R828_WgetDirectIpTarHttpGetRule(),
        "R829" => new R829_ZipTldExecutableHttpGetRule(),
        "R830" => new R830_DirectIpDistinctExecutableGetRule(),
        "R831" => new R831_MpCmdRunDirectIpArchiveGetRule(),
        "R832" => new R832_CertocPublicIpHttpGetRule(),
        "R833" => new R833_WordRemoteTemplateThenPowerShellTlsRule(),
        "R834" => new R834_DgaLikeDnsBurstThenScriptTlsRule(),
        "R835" => new R835_MshtaFetchThenRundll32TlsRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static int Threshold(string id) => id switch { "R827" => 3, "R834" => 5, "R826" or "R830" or "R833" or "R835" => 2, _ => 1 };

    private static TrafficRecord Packet(string id, int stage)
    {
        var r = new TrafficRecord
        {
            Id = Guid.NewGuid(), IpVersion = 4, Source = "10.1.1.10", Destination = "8.8.8.8",
            Protocol = "TCP", IsTcp = true, IsUdp = false,
            SourcePort = 51000, DestinationPort = 443, TcpFlags = 0x02,
            L4Len = 0, Length = 40, ProcessName = "notepad.exe", ProcessId = 840,
            Info = "PRIVATE-RAW-EVIDENCE-MARKER"
        };
        switch (id)
        {
            case "R826":
                r.Destination = stage == 0 ? "8.8.8.8" : "9.9.9.9";
                r.DestinationPort = 8443;
                break;
            case "R827":
                r.ProcessName = "finger.exe"; r.Destination = "9.9.9." + (stage + 1);
                r.DestinationPort = 79;
                break;
            case "R828":
                r.ProcessName = "wget"; r.DestinationPort = 80;
                Http(r, "GET", "/archive/payload.tar", "8.8.8.8");
                break;
            case "R829":
                r.DestinationPort = 80; r.ProcessName = "chrome.exe";
                Http(r, "GET", "/downloads/installer.exe", "updates.vendor.zip");
                break;
            case "R830":
                r.ProcessName = "chrome.exe"; r.DestinationPort = 80;
                Http(r, "GET", stage == 0 ? "/stage.exe" : "/stage.dll", "8.8.8.8");
                break;
            case "R831":
                r.ProcessName = "MpCmdRun.exe"; r.DestinationPort = 80;
                Http(r, "GET", "/bin/update.cab", "8.8.8.8");
                break;
            case "R832":
                r.ProcessName = "CertOC.exe"; r.DestinationPort = 80;
                Http(r, "GET", "/cacaps", "8.8.8.8");
                break;
            case "R833":
                if (stage == 0)
                {
                    r.ProcessName = "winword.exe"; r.DestinationPort = 80;
                    Http(r, "GET", "/templates/report.dotm", "templates.example.net");
                }
                else
                {
                    r.ProcessName = "powershell.exe"; r.Destination = "9.9.9.9";
                    Tls(r, 8443, 540, "relay.example.net");
                }
                break;
            case "R834":
                r.ProcessName = "wscript.exe";
                if (stage < 4)
                {
                    r.Protocol = "UDP"; r.IsTcp = false; r.IsUdp = true; r.TcpFlags = null;
                    r.DestinationPort = 53; r.SourcePort = 53533;
                    r.ApplicationProtocol = "DNS"; r.DnsQtype = "A";
                    r.DnsQname = "x9q2v7p4m8z1d6k3t" + stage + ".dynamic.example.net";
                    r.L4Len = 96; r.Length = 124;
                }
                else { r.Destination = "9.9.9.9"; Tls(r, 8443, 640, "beacon.example.net"); }
                break;
            case "R835":
                if (stage == 0)
                {
                    r.ProcessName = "mshta.exe"; r.DestinationPort = 80;
                    Http(r, "GET", "/stager/entry.hta", "delivery.example.net");
                }
                else
                {
                    r.ProcessName = "rundll32.exe"; r.Destination = "9.9.9.9";
                    Tls(r, 8443, 700, "control.example.net");
                }
                break;
        }
        return r;
    }

    private static void Http(TrafficRecord r, string method, string uri, string host)
    {
        r.TcpFlags = 0x18; r.L4Len = 420; r.Length = 460;
        r.ApplicationProtocol = "HTTP"; r.HttpMethod = method; r.HttpUri = uri; r.HttpHost = host;
    }

    private static void Tls(TrafficRecord r, int port, int size, string host)
    {
        r.DestinationPort = port; r.TcpFlags = 0x18; r.L4Len = size; r.Length = size + 40;
        r.TlsVersion = "TLS1.3"; r.Sni = host;
    }

    private static RuleEvaluationContext At(TrafficRecord record, double seconds)
        => new(record, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, double at)
    {
        RuleEvaluationResult? result = null;
        for (var i = 0; i < Threshold(id); i++)
            result = await rule.EvaluateAsync(At(Packet(id, i), at + i * 3));
        return result!;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task CoherentPositiveMatchesButContradictoryOrMissingPeerFails(string id)
    {
        Assert.True((await Trigger(Rule(id), id, 0)).Matched);
        var contradictory = Rule(id); var missing = Rule(id);
        for (var i = 0; i < Threshold(id); i++)
        {
            var wrongFlags = Packet(id, i); wrongFlags.IsTcp = true; wrongFlags.IsUdp = true;
            Assert.False((await contradictory.EvaluateAsync(At(wrongFlags, i * 3))).Matched);
            var noDestination = Packet(id, i); noDestination.Destination = null;
            Assert.False((await missing.EvaluateAsync(At(noDestination, i * 3))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task BenignNearMissNeverTriggers(string id)
    {
        var rule = Rule(id);
        for (var i = 0; i < Threshold(id) + 2; i++)
        {
            var stage = i % Threshold(id); var record = Packet(id, stage);
            switch (id)
            {
                case "R829": record.HttpHost = "updates.vendor.com"; break;
                case "R830": record.HttpHost = "downloads.example.net"; break;
                case "R834": record.DnsQname = "www.example.net"; record.TlsVersion = null; break;
                case "R833": record.HttpUri = "/templates/report.docx"; record.TlsVersion = null; break;
                case "R835": record.HttpUri = "/stager/entry.html"; record.TlsVersion = null; break;
                default: record.ProcessName = "explorer.exe"; break;
            }
            Assert.False((await rule.EvaluateAsync(At(record, i * 3))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task DuplicateReverseClockAndExpiredEvidenceDoNotTrigger(string id)
    {
        var rule = Rule(id); var first = Packet(id, 0);
        await rule.EvaluateAsync(At(first, 10));
        for (var i = 1; i < Threshold(id); i++)
        {
            var repeated = Packet(id, i); repeated.Id = first.Id;
            Assert.False((await rule.EvaluateAsync(At(repeated, 10 + i * 3))).Matched);
        }
        Assert.False((await rule.EvaluateAsync(At(first, 9))).Matched);
        if (Threshold(id) > 1)
        {
            var expired = Rule(id);
            await expired.EvaluateAsync(At(Packet(id, 0), 0));
            for (var i = 1; i < Threshold(id); i++)
                Assert.False((await expired.EvaluateAsync(At(Packet(id, i), 251 + i * 3))).Matched);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task CooldownRecoversAndRawInfoNeverAppearsInEvent(string id)
    {
        var rule = Rule(id);
        var result = await Trigger(rule, id, 0);
        Assert.True(result.Matched);
        Assert.DoesNotContain("PRIVATE-RAW-EVIDENCE-MARKER", JsonSerializer.Serialize(result.Events));
        Assert.True((await Trigger(rule, id, 300)).Suppressed);
        Assert.True((await Trigger(rule, id, 940)).Matched);
    }

    [Fact]
    public async Task FanoutCannotReuseOneDestination()
    {
        foreach (var id in new[] { "R826", "R827" })
        {
            var rule = Rule(id);
            for (var i = 0; i < 6; i++)
            {
                var record = Packet(id, i % Threshold(id)); record.Destination = "9.9.9.1";
                Assert.False((await rule.EvaluateAsync(At(record, i * 3))).Matched);
            }
        }
    }

    [Fact]
    public async Task DifferentDirectIpExecutablePathsAreRequired()
    {
        var rule = Rule("R830");
        await rule.EvaluateAsync(At(Packet("R830", 0), 0));
        var duplicatePath = Packet("R830", 1); duplicatePath.HttpUri = "/stage.exe";
        Assert.False((await rule.EvaluateAsync(At(duplicatePath, 3))).Matched);
    }

    [Theory]
    [InlineData("R833")]
    [InlineData("R835")]
    public async Task DifferentPublicPeerRequiredForSecondStage(string id)
    {
        var rule = Rule(id);
        await rule.EvaluateAsync(At(Packet(id, 0), 0));
        var samePeer = Packet(id, 1); samePeer.Destination = "8.8.8.8";
        Assert.False((await rule.EvaluateAsync(At(samePeer, 3))).Matched);
    }

    [Theory]
    [InlineData("R833")]
    [InlineData("R834")]
    [InlineData("R835")]
    public async Task TlsFinalStageRejectsContradictoryHttpOrDnsMetadata(string id)
    {
        var rule = Rule(id);
        for (var i = 0; i < Threshold(id) - 1; i++)
            await rule.EvaluateAsync(At(Packet(id, i), i * 3));
        var contradictory = Packet(id, Threshold(id) - 1);
        contradictory.ApplicationProtocol = "HTTP";
        contradictory.HttpUri = "/contradictory";
        Assert.False((await rule.EvaluateAsync(At(contradictory, 20))).Matched);
    }

    [Fact]
    public async Task NeighboringRulesDoNotConverge()
    {
        for (var i = 0; i < Ids.Length; i++)
        {
            var rule = Rule(Ids[i]); var neighbor = Ids[(i + 1) % Ids.Length];
            for (var stage = 0; stage < Threshold(neighbor) + 2; stage++)
                Assert.False((await rule.EvaluateAsync(At(Packet(neighbor, stage % Threshold(neighbor)), stage * 3))).Matched);
        }
    }

    [Fact]
    public void RegistryHasOneCandidateShadowRulePerId()
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
    { "R826", "R827", "R828", "R829", "R830", "R831", "R832", "R833", "R834", "R835" };
}
