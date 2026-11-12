// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Test source authored before detectors.
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
public sealed class R926R945ObservableCandidateBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 12, 0, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids = { "R926", "R927", "R928", "R929", "R930", "R931", "R932", "R933", "R934", "R935", "R936", "R937", "R938", "R939", "R940", "R941", "R942", "R943", "R944", "R945" };
    public static TheoryData<string> Cases => new() { "R926", "R927", "R928", "R929", "R930", "R931", "R932", "R933", "R934", "R935", "R936", "R937", "R938", "R939", "R940", "R941", "R942", "R943", "R944", "R945" };
    private static IDetectionRule Rule(string id) => id switch
    {
        "R926" => new R926_OdbcconfPublicDllHttpGetRule(),
        "R927" => new R927_CscriptPublicScriptletHttpGetRule(),
        "R928" => new R928_JamplusPublicJamHttpGetRule(),
        "R929" => new R929_DfsvcManifestThenPublicTlsRule(),
        "R930" => new R930_MsbuildTargetsGetThenPublicSmbRule(),
        "R931" => new R931_NtlmrelayxPrivateSmbThenLdapSynRule(),
        "R932" => new R932_PublicMqttControlPublishRule(),
        "R933" => new R933_MqttSynThenRetainedPublishRule(),
        "R934" => new R934_MqttBrokerTlsDifferentPublicPeersRule(),
        "R935" => new R935_HostdSynThenEqualIssuerSubjectCertRule(),
        "R936" => new R936_PythonPublicTlsCertificateValidityInversionRule(),
        "R937" => new R937_IdeMacMarketplaceThenSshPublicSynRule(),
        "R938" => new R938_OllamaPublicEmbeddingHttpPostRule(),
        "R939" => new R939_CurlPublicRepeatedUploadCadenceRule(),
        "R940" => new R940_TeamviewerPublic5938TlsRule(),
        "R941" => new R941_PublicProxySynThenPrivateSocksSynRule(),
        "R942" => new R942_PrivateSmbWriteThenModbusSynRule(),
        "R943" => new R943_InstallutilPublicMsiGetThenTlsRule(),
        "R944" => new R944_MshtaHtaGetThenPrivateWinRmSynRule(),
        "R945" => new R945_OsascriptPublicDiscordWebhookPostRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };
    private static TrafficRecord[] Packets(string id) => id switch
    {
        "R926" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "odbcconf.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, ApplicationProtocol = "HTTP", HttpMethod = "GET", HttpUri = "/driver.dll", HttpHost = "service.example.net" } },
        "R927" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "cscript.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, ApplicationProtocol = "HTTP", HttpMethod = "GET", HttpUri = "/script.sct", HttpHost = "service.example.net" } },
        "R928" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "jamplus.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, ApplicationProtocol = "HTTP", HttpMethod = "GET", HttpUri = "/build.jam", HttpHost = "service.example.net" } },
        "R929" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "dfsvc.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, ApplicationProtocol = "HTTP", HttpMethod = "GET", HttpUri = "/deploy.application", HttpHost = "service.example.net" }, new TrafficRecord { Source = "10.1.1.10", Destination = "9.9.9.9", SourcePort = 51000, DestinationPort = 443, ProcessId = 310, ProcessName = "dfsvc.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, TlsVersion = "TLS1.3", Sni = "updates.example.net" } },
        "R930" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "msbuild.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, ApplicationProtocol = "HTTP", HttpMethod = "GET", HttpUri = "/build.targets", HttpHost = "service.example.net" }, new TrafficRecord { Source = "10.1.1.10", Destination = "9.9.9.9", SourcePort = 51000, DestinationPort = 445, ProcessId = 310, ProcessName = "msbuild.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R931" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 445, ProcessId = 310, ProcessName = "ntlmrelayx.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.3.77", SourcePort = 51000, DestinationPort = 389, ProcessId = 310, ProcessName = "ntlmrelayx.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R932" => new[] { new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 1883, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, MqttPublishTopicObserved = true, MqttControlTopicObserved = true } },
        "R933" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 1883, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 1883, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, MqttPublishTopicObserved = true, MqttControlTopicObserved = true, MqttRetain = true } },
        "R934" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 8883, ProcessId = 310, ProcessName = "mosquitto_pub", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, TlsVersion = "TLS1.3", Sni = "broker1.example.net" }, new TrafficRecord { Source = "10.1.1.10", Destination = "9.9.9.9", SourcePort = 51000, DestinationPort = 8883, ProcessId = 310, ProcessName = "mosquitto_pub", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, TlsVersion = "TLS1.3", Sni = "broker2.example.net" } },
        "R935" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 443, ProcessId = 310, ProcessName = "hostd", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.1.10", SourcePort = 443, DestinationPort = 51000, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, TlsVersion = "TLS1.2", CertIssuer = "CN=Lab", CertSubject = "CN=Lab" } },
        "R936" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 443, ProcessId = 310, ProcessName = "python", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.1.10", SourcePort = 443, DestinationPort = 51000, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, TlsVersion = "TLS1.2", CertValidFrom = Epoch.AddDays(3), CertValidTo = Epoch.AddDays(1) } },
        "R937" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 443, ProcessId = 310, ProcessName = "code", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, TlsVersion = "TLS1.3", Sni = "marketplace.visualstudio.com" }, new TrafficRecord { Source = "10.1.1.10", Destination = "9.9.9.9", SourcePort = 51000, DestinationPort = 22, ProcessId = 310, ProcessName = "code", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R938" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 11434, ProcessId = 310, ProcessName = "ollama", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, ApplicationProtocol = "HTTP", HttpMethod = "POST", HttpUri = "/api/embed", HttpHost = "service.example.net" } },
        "R939" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "curl.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, ApplicationProtocol = "HTTP", HttpMethod = "POST", HttpUri = "/upload", HttpHost = "service.example.net" }, new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "curl.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, ApplicationProtocol = "HTTP", HttpMethod = "POST", HttpUri = "/upload", HttpHost = "service.example.net" }, new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "curl.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, ApplicationProtocol = "HTTP", HttpMethod = "POST", HttpUri = "/upload", HttpHost = "service.example.net" }, new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "curl.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, ApplicationProtocol = "HTTP", HttpMethod = "POST", HttpUri = "/upload", HttpHost = "service.example.net" } },
        "R940" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 5938, ProcessId = 310, ProcessName = "teamviewer.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, TlsVersion = "TLS1.3", Sni = "router.teamviewer.com" } },
        "R941" => new[] { new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 3128, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.2.45", Destination = "10.1.3.77", SourcePort = 51000, DestinationPort = 1080, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R942" => new[] { Smb2CaptureQualificationTests.WritePacket("10.1.1.10", "10.1.2.45", null, 0), new TrafficRecord { Source = "10.1.2.45", Destination = "10.1.3.77", SourcePort = 51000, DestinationPort = 502, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R943" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "installutil.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, ApplicationProtocol = "HTTP", HttpMethod = "GET", HttpUri = "/package.msi", HttpHost = "service.example.net" }, new TrafficRecord { Source = "10.1.1.10", Destination = "9.9.9.9", SourcePort = 51000, DestinationPort = 443, ProcessId = 310, ProcessName = "installutil.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, TlsVersion = "TLS1.3", Sni = "service.example.net" } },
        "R944" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "mshta.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, ApplicationProtocol = "HTTP", HttpMethod = "GET", HttpUri = "/script.hta", HttpHost = "service.example.net" }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 5985, ProcessId = 310, ProcessName = "mshta.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R945" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "osascript", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 760, L4Len = 720, ApplicationProtocol = "HTTP", HttpMethod = "POST", HttpUri = "/api/webhooks/123/example", HttpHost = "discord.com" } },
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };
    private static RuleEvaluationContext At(TrafficRecord r, double seconds)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));
    private static int Step(string id) => id == "R939" ? 10 : 3;
    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, int start)
    {
        var records = Packets(id); RuleEvaluationResult? last = null;
        for (var i = 0; i < records.Length; i++)
        {
            last = await rule.EvaluateAsync(At(records[i], start + i * Step(id)));
            if (i < records.Length - 1) Assert.False(last.Matched);
        }
        return last!;
    }
    [Theory, MemberData(nameof(Cases))]
    public async Task PositiveAndPrivacy(string id)
    {
        var result = await Trigger(Rule(id), id, 0);
        Assert.True(result.Matched);
        Assert.DoesNotContain("RAW-INFO-PRIVATE-MARKER", JsonSerializer.Serialize(result.Events));
    }
    [Theory, MemberData(nameof(Cases))]
    public async Task MissingContradictoryAndEmptyId(string id)
    {
        foreach (var variant in new[] { "missing", "transport", "id" })
        {
            var rule = Rule(id); var records = Packets(id);
            for (var i = 0; i < records.Length; i++)
            {
                var r = records[i];
                if (variant == "missing") r.Destination = null;
                if (variant == "transport") r.IsTcp = r.IsUdp = true;
                if (variant == "id") r.Id = Guid.Empty;
                Assert.False((await rule.EvaluateAsync(At(r, i * Step(id)))).Matched);
            }
        }
    }
    [Theory, MemberData(nameof(Cases))]
    public async Task SpecificNearMiss(string id)
    {
        var rule = Rule(id); var records = Packets(id);
        for (var i = 0; i < records.Length; i++)
        {
            var r = records[i];
            switch (id)
            {
                case "R926": r.HttpUri = "/driver.dll.txt"; break;
                case "R927": r.HttpUri = "/script.sct.txt"; break;
                case "R928": r.HttpUri = "/build.jam.txt"; break;
                case "R929": r.ProcessName = "explorer.exe"; break;
                case "R930": r.ProcessName = "explorer.exe"; break;
                case "R931": r.ProcessName = "explorer.exe"; break;
                case "R932": r.MqttControlTopicObserved = false; break;
                case "R933": r.DestinationPort = 1884; break;
                case "R934": r.DestinationPort = 8884; break;
                case "R935": r.SourcePort = 444; r.DestinationPort = 444; break;
                case "R936": r.SourcePort = 444; r.DestinationPort = 444; break;
                case "R937": r.ProcessName = "explorer.exe"; break;
                case "R938": r.HttpUri = "/api/tags"; break;
                case "R939": r.HttpMethod = "GET"; break;
                case "R940": r.Sni = "teamviewer.com.example.net"; break;
                case "R941": r.DestinationPort = 3129; break;
                case "R942": r.DestinationPort = 503; break;
                case "R943": r.ProcessName = "explorer.exe"; break;
                case "R944": r.ProcessName = "explorer.exe"; break;
                case "R945": r.HttpHost = "discord.com.example.net"; break;
            }
            Assert.False((await rule.EvaluateAsync(At(r, i * Step(id)))).Matched);
        }
    }
    [Theory, MemberData(nameof(Cases))]
    public async Task DuplicateReverseAndExpiry(string id)
    {
        var records = Packets(id); var rule = Rule(id);
        await rule.EvaluateAsync(At(records[0], 100));
        if (records.Length == 1)
        {
            Assert.False((await rule.EvaluateAsync(At(records[0], 101))).Matched);
            Assert.False((await rule.EvaluateAsync(At(Packets(id)[0], 99))).Matched);
            return;
        }
        for (var i = 1; i < records.Length; i++)
        {
            records[i].Id = records[0].Id;
            Assert.False((await rule.EvaluateAsync(At(records[i], 100 + i * Step(id)))).Matched);
        }
        var reverse = Rule(id); var expired = Rule(id); records = Packets(id);
        await reverse.EvaluateAsync(At(records[0], 100));
        await expired.EvaluateAsync(At(records[0], 0));
        for (var i = 1; i < records.Length; i++)
        {
            Assert.False((await reverse.EvaluateAsync(At(records[i], 100 - i * Step(id)))).Matched);
            Assert.False((await expired.EvaluateAsync(At(records[i], 90 * i))).Matched);
        }
    }
    [Theory, MemberData(nameof(Cases))]
    public async Task CooldownRecovery(string id)
    {
        var rule = Rule(id);
        Assert.True((await Trigger(rule, id, 0)).Matched);
        Assert.True((await Trigger(rule, id, 300)).Suppressed);
        Assert.True((await Trigger(rule, id, 950)).Matched);
    }
    [Fact]
    public async Task CorrelationRejectsUnrelatedPidAndFlow()
    {
        foreach (var id in new[] { "R929", "R930", "R931", "R937", "R943", "R944" })
        {
            var rule = Rule(id); var records = Packets(id);
            await rule.EvaluateAsync(At(records[0], 0)); records[1].ProcessId++;
            Assert.False((await rule.EvaluateAsync(At(records[1], 3))).Matched);
        }
        foreach (var id in new[] { "R933", "R935", "R936" })
        {
            var rule = Rule(id); var records = Packets(id);
            await rule.EvaluateAsync(At(records[0], 0));
            if (id == "R933") records[1].SourcePort++; else records[1].DestinationPort++;
            Assert.False((await rule.EvaluateAsync(At(records[1], 3))).Matched);
        }
    }
    [Fact]
    public async Task MqttRetainAndDistinctPeersAreRequired()
    {
        var retained = Rule("R933"); var records = Packets("R933");
        await retained.EvaluateAsync(At(records[0], 0)); records[1].MqttRetain = false;
        Assert.False((await retained.EvaluateAsync(At(records[1], 3))).Matched);
        var distinct = Rule("R934"); records = Packets("R934");
        await distinct.EvaluateAsync(At(records[0], 0)); records[1].Destination = records[0].Destination;
        Assert.False((await distinct.EvaluateAsync(At(records[1], 3))).Matched);
    }
    [Fact]
    public async Task CadenceRequiresSpacing()
    {
        var rule = Rule("R939"); var records = Packets("R939");
        for (var i = 0; i < records.Length; i++)
            Assert.False((await rule.EvaluateAsync(At(records[i], i))).Matched);
    }
    [Fact]
    public async Task IndependentInstances()
    {
        foreach (var id in Ids)
        {
            Assert.True((await Trigger(Rule(id), id, 0)).Matched);
            Assert.True((await Trigger(Rule(id), id, 0)).Matched);
        }
    }
    [Fact]
    public void RegistryUniqueCandidateShadow()
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
}
