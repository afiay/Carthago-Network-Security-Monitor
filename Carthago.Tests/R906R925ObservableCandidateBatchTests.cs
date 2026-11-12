// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Test source authored first; zero tests/builds executed.
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
public sealed class R906R925ObservableCandidateBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 12, 0, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids = { "R906", "R907", "R908", "R909", "R910", "R911", "R912", "R913", "R914", "R915", "R916", "R917", "R918", "R919", "R920", "R921", "R922", "R923", "R924", "R925" };
    public static TheoryData<string> Cases => new() { "R906", "R907", "R908", "R909", "R910", "R911", "R912", "R913", "R914", "R915", "R916", "R917", "R918", "R919", "R920", "R921", "R922", "R923", "R924", "R925" };
    private static IDetectionRule Rule(string id) => id switch
    {
        "R906" => new R906_Rundll32PublicSmbSynThenDataRule(),
        "R907" => new R907_MshtaPublicDisguisedArtifactGetRule(),
        "R908" => new R908_PublicSmbSynThenParsedWriteRule(),
        "R909" => new R909_PrivateSshIngressThenPublicRdpSynRule(),
        "R910" => new R910_PowershellLdapSynThenSmbWriteRule(),
        "R911" => new R911_RsyncPrivatePeerDataFanoutRule(),
        "R912" => new R912_PublicSshThenBusyboxPrivateRsyncRule(),
        "R913" => new R913_HostdPublicSshDataBurstRule(),
        "R914" => new R914_Rundll32SynThenFutureCertificateRule(),
        "R915" => new R915_DsconfigadLdapThenKerberosSynRule(),
        "R916" => new R916_HostdPublicDnsQueryNxdomainReplyRule(),
        "R917" => new R917_PrivateRdpThenOtherHostWinRmSynRule(),
        "R918" => new R918_PowershellModbusWriteThenPublicTlsRule(),
        "R919" => new R919_PsexecSmbWriteThenRpcSynRule(),
        "R920" => new R920_PowershellScriptGetThenPublicTlsRule(),
        "R921" => new R921_AnydeskPublic6568ThenTlsRule(),
        "R922" => new R922_PublicPswaLoginRequestRule(),
        "R923" => new R923_IisWorkerPublicAspxPostRule(),
        "R924" => new R924_PublicRdpThenPrivateSmbSynRule(),
        "R925" => new R925_BitsadminPrivateSmbThenPublicHttpGetRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };
    private static TrafficRecord[] Packets(string id) => id switch
    {
        "R906" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 445, ProcessId = 310, ProcessName = "rundll32.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 445, ProcessId = 310, ProcessName = "rundll32.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700 } },
        "R907" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "mshta.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, ApplicationProtocol = "HTTP", HttpMethod = "GET", HttpUri = "/artifact.png", HttpHost = "service.example.net" } },
        "R908" => new[] { new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 445, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 445, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, ApplicationProtocol = "smb2.write.request" } },
        "R909" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 22, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.2.45", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 3389, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R910" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 389, ProcessId = 310, ProcessName = "powershell.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 445, ProcessId = 310, ProcessName = "powershell.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, ApplicationProtocol = "smb2.write.request" } },
        "R911" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 873, ProcessId = 310, ProcessName = "rsync", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700 }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.3.77", SourcePort = 51000, DestinationPort = 873, ProcessId = 310, ProcessName = "rsync", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700 }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.4.55", SourcePort = 51000, DestinationPort = 873, ProcessId = 310, ProcessName = "rsync", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700 } },
        "R912" => new[] { new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 22, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.2.45", Destination = "10.1.3.77", SourcePort = 51000, DestinationPort = 873, ProcessId = 310, ProcessName = "busybox", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700 } },
        "R913" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 22, ProcessId = 310, ProcessName = "hostd", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700 }, new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 22, ProcessId = 310, ProcessName = "hostd", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700 }, new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 22, ProcessId = 310, ProcessName = "hostd", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700 }, new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 22, ProcessId = 310, ProcessName = "hostd", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700 } },
        "R914" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 443, ProcessId = 310, ProcessName = "rundll32.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.1.10", SourcePort = 443, DestinationPort = 51000, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, TlsVersion = "TLS1.2", CertIssuer = "Lab Issuer", CertSubject = "Lab Subject", CertValidFrom = Epoch.AddDays(3), CertValidTo = Epoch.AddDays(30) } },
        "R915" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 389, ProcessId = 310, ProcessName = "dsconfigad", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 88, ProcessId = 310, ProcessName = "dsconfigad", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R916" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 53, ProcessId = 310, ProcessName = "hostd", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsUdp = true, Protocol = "UDP", Length = 128, L4Len = 100, ApplicationProtocol = "DNS", DnsQname = "lookup.example.net", DnsQtype = "A", DnsRcode = "NOERROR" }, new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.1.10", SourcePort = 53, DestinationPort = 51000, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsUdp = true, Protocol = "UDP", Length = 128, L4Len = 100, ApplicationProtocol = "DNS", DnsQname = "lookup.example.net", DnsQtype = "A", DnsRcode = "NXDOMAIN", DnsIsResponse = true } },
        "R917" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 3389, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.2.45", Destination = "10.1.3.77", SourcePort = 51000, DestinationPort = 5985, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R918" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 502, ProcessId = 310, ProcessName = "powershell.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 100, L4Len = 60, ApplicationProtocol = "modbus.write" }, new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 443, ProcessId = 310, ProcessName = "powershell.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, TlsVersion = "TLS1.3", Sni = "service.example.net" } },
        "R919" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 445, ProcessId = 310, ProcessName = "psexec.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, ApplicationProtocol = "smb2.write.request" }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 135, ProcessId = 310, ProcessName = "psexec.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R920" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "powershell.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, ApplicationProtocol = "HTTP", HttpMethod = "GET", HttpUri = "/artifact.ps1", HttpHost = "service.example.net" }, new TrafficRecord { Source = "10.1.1.10", Destination = "9.9.9.9", SourcePort = 51000, DestinationPort = 443, ProcessId = 310, ProcessName = "powershell.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, TlsVersion = "TLS1.3", Sni = "service.example.net" } },
        "R921" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 6568, ProcessId = 310, ProcessName = "anydesk.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 443, ProcessId = 310, ProcessName = "anydesk.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, TlsVersion = "TLS1.3", Sni = "service.example.net" } },
        "R922" => new[] { new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 80, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, ApplicationProtocol = "HTTP", HttpMethod = "POST", HttpUri = "/pswa/default.aspx", HttpHost = "service.example.net" } },
        "R923" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "w3wp.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, ApplicationProtocol = "HTTP", HttpMethod = "POST", HttpUri = "/artifact.aspx", HttpHost = "service.example.net" } },
        "R924" => new[] { new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 3389, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.2.45", Destination = "10.1.3.77", SourcePort = 51000, DestinationPort = 445, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R925" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 445, ProcessId = 310, ProcessName = "bitsadmin.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "bitsadmin.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "SECRET-RAW-INFO-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, ApplicationProtocol = "HTTP", HttpMethod = "GET", HttpUri = "/artifact.bin", HttpHost = "service.example.net" } },
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };
    private static RuleEvaluationContext At(TrafficRecord r, double seconds)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));
    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, int start)
    {
        var records = Packets(id); RuleEvaluationResult? last = null;
        for (var i = 0; i < records.Length; i++)
        {
            last = await rule.EvaluateAsync(At(records[i], start + i * 3));
            if (i < records.Length - 1) Assert.False(last.Matched);
        }
        return last!;
    }
    [Theory, MemberData(nameof(Cases))]
    public async Task PositiveAndPrivacy(string id)
    {
        var result = await Trigger(Rule(id), id, 0);
        Assert.True(result.Matched);
        Assert.DoesNotContain("SECRET-RAW-INFO-MARKER", JsonSerializer.Serialize(result.Events));
    }
    [Theory, MemberData(nameof(Cases))]
    public async Task MissingContradictoryEmptyIdAndNearMiss(string id)
    {
        foreach (var variant in new[] { "missing", "transport", "id", "port" })
        {
            var rule = Rule(id); var records = Packets(id);
            for (var i = 0; i < records.Length; i++)
            {
                var r = records[i];
                if (variant == "missing") r.Destination = null;
                if (variant == "transport") r.IsTcp = r.IsUdp = true;
                if (variant == "id") r.Id = Guid.Empty;
                if (variant == "port") { r.DestinationPort = 65000; r.SourcePort = 65001; }
                Assert.False((await rule.EvaluateAsync(At(r, i * 3))).Matched);
            }
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
            Assert.False((await rule.EvaluateAsync(At(records[i], 100 + i))).Matched);
        }
        var reverse = Rule(id); var expired = Rule(id); records = Packets(id);
        await reverse.EvaluateAsync(At(records[0], 100));
        await expired.EvaluateAsync(At(records[0], 0));
        for (var i = 1; i < records.Length; i++)
        {
            Assert.False((await reverse.EvaluateAsync(At(records[i], 100 - i))).Matched);
            Assert.False((await expired.EvaluateAsync(At(records[i], 60 * i))).Matched);
        }
    }
    [Theory, MemberData(nameof(Cases))]
    public async Task CooldownAndRecovery(string id)
    {
        var rule = Rule(id);
        Assert.True((await Trigger(rule, id, 0)).Matched);
        Assert.True((await Trigger(rule, id, 300)).Suppressed);
        Assert.True((await Trigger(rule, id, 950)).Matched);
    }
    [Theory, MemberData(nameof(Cases))]
    public async Task DistinctInstancesHaveIndependentState(string id)
    {
        Assert.True((await Trigger(Rule(id), id, 0)).Matched);
        Assert.True((await Trigger(Rule(id), id, 0)).Matched);
    }
    [Fact]
    public async Task CorrelationRejectsDifferentFlowOrPid()
    {
        foreach (var id in new[] { "R906", "R908", "R914", "R916" })
        {
            var rule = Rule(id); var records = Packets(id);
            await rule.EvaluateAsync(At(records[0], 0));
            if (id is "R914" or "R916") records[1].DestinationPort++;
            else records[1].SourcePort++;
            Assert.False((await rule.EvaluateAsync(At(records[1], 3))).Matched);
        }
        foreach (var id in new[] { "R910", "R915", "R919", "R921" })
        {
            var rule = Rule(id); var records = Packets(id);
            await rule.EvaluateAsync(At(records[0], 0)); records[1].ProcessId++;
            Assert.False((await rule.EvaluateAsync(At(records[1], 3))).Matched);
        }
        var dns = Rule("R916"); var pair = Packets("R916");
        await dns.EvaluateAsync(At(pair[0], 0)); pair[1].DnsQname = "other.example.net";
        Assert.False((await dns.EvaluateAsync(At(pair[1], 3))).Matched);
    }
    [Fact]
    public async Task DistinctRsyncPeersRequired()
    {
        var rule = Rule("R911"); var records = Packets("R911");
        for (var i = 0; i < records.Length; i++)
        { records[i].Destination = records[0].Destination; Assert.False((await rule.EvaluateAsync(At(records[i], i * 3))).Matched); }
    }
    [Fact]
    public async Task ParserLabelsCannotBeReplacedByInfo()
    {
        foreach (var id in new[] { "R908", "R910", "R918", "R919" })
        {
            var rule = Rule(id); var records = Packets(id);
            for (var i = 0; i < records.Length; i++)
            {
                if (records[i].ApplicationProtocol != null)
                { records[i].Info = records[i].ApplicationProtocol; records[i].ApplicationProtocol = null; }
                Assert.False((await rule.EvaluateAsync(At(records[i], i * 3))).Matched);
            }
        }
    }
    [Fact]
    public async Task SpecificNearMisses()
    {
        foreach (var id in new[] { "R907", "R922", "R923" })
        {
            var r = Packets(id)[0]; r.HttpUri += ".bak";
            Assert.False((await Rule(id).EvaluateAsync(At(r, 0))).Matched);
        }
        var cert = Rule("R914"); var pair = Packets("R914");
        await cert.EvaluateAsync(At(pair[0], 0)); pair[1].CertValidFrom = Epoch.AddHours(-1);
        Assert.False((await cert.EvaluateAsync(At(pair[1], 3))).Matched);
        var dns = Rule("R916"); pair = Packets("R916");
        await dns.EvaluateAsync(At(pair[0], 0)); pair[1].DnsRcode = "NOERROR";
        Assert.False((await dns.EvaluateAsync(At(pair[1], 3))).Matched);
    }
    [Fact]
    public async Task NewBatchPredicatesStayIndependent()
    {
        foreach (var id in Ids)
            foreach (var other in Ids.Where(x => x != id))
            {
                var rule = Rule(id); var records = Packets(other);
                for (var i = 0; i < records.Length; i++)
                    Assert.False((await rule.EvaluateAsync(At(records[i], i * 3))).Matched);
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
