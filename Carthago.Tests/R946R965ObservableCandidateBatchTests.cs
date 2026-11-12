// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Test source authored first.
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
public sealed class R946R965ObservableCandidateBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 12, 0, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids = { "R946", "R947", "R948", "R949", "R950", "R951", "R952", "R953", "R954", "R955", "R956", "R957", "R958", "R959", "R960", "R961", "R962", "R963", "R964", "R965" };
    public static TheoryData<string> Cases => new() { "R946", "R947", "R948", "R949", "R950", "R951", "R952", "R953", "R954", "R955", "R956", "R957", "R958", "R959", "R960", "R961", "R962", "R963", "R964", "R965" };
    private static IDetectionRule Rule(string id) => id switch
    {
        "R946" => new R946_PrivateTftpRequestThenEphemeralReplyRule(),
        "R947" => new R947_PrivateSshIngressThenPublicTftpRule(),
        "R948" => new R948_PrivateFtpStorThenSshSynRule(),
        "R949" => new R949_PrivateFtpStorThenTftpDataRule(),
        "R950" => new R950_PowershellPrivateScriptGetThenSmbWriteRule(),
        "R951" => new R951_TeamsPublicTlsThenPublicSmbRule(),
        "R952" => new R952_WscriptPublicVbsGetThenTlsRule(),
        "R953" => new R953_CscriptPrivateJsGetThenRpcSynRule(),
        "R954" => new R954_PublicPhpGetThenBashPublic4444SynRule(),
        "R955" => new R955_PublicAspxPostThenW3wpPublicWinRmRule(),
        "R956" => new R956_NetPrivateRpcThenLdapRule(),
        "R957" => new R957_WmicPrivateRpcThenSmbRule(),
        "R958" => new R958_CurlConnectivityGetThenPrivate902SynRule(),
        "R959" => new R959_PowershellPublicDnsPortSynThenTlsRule(),
        "R960" => new R960_PrivateSshPortPayloadCadenceRule(),
        "R961" => new R961_PublicProxyIngressThenPrivateModbusSynRule(),
        "R962" => new R962_CliDnsQueryLowTtlReplyChurnRule(),
        "R963" => new R963_PublicSshIngressThenSshdPublicTlsRule(),
        "R964" => new R964_OpensslPublic8443ThenSamePeer443TlsRule(),
        "R965" => new R965_SpoolsvPublicDllGetThenSmbSynRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };
    private static TrafficRecord[] Packets(string id) => id switch
    {
        "R946" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 69, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsUdp = true, Protocol = "UDP", Length = 128, L4Len = 100 }, new TrafficRecord { Source = "10.1.2.45", Destination = "10.1.1.10", SourcePort = 52000, DestinationPort = 51000, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsUdp = true, Protocol = "UDP", Length = 128, L4Len = 100 } },
        "R947" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 22, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.2.45", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 69, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsUdp = true, Protocol = "UDP", Length = 128, L4Len = 100 } },
        "R948" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 21, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 140, L4Len = 100, ApplicationProtocol = "ftp.stor" }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 22, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R949" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 21, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 140, L4Len = 100, ApplicationProtocol = "ftp.stor" }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 69, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsUdp = true, Protocol = "UDP", Length = 128, L4Len = 100 } },
        "R950" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "powershell.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, ApplicationProtocol = "HTTP", HttpMethod = "GET", HttpUri = "/scripts/login.ps1", HttpHost = "service.example.net" }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 445, ProcessId = 310, ProcessName = "powershell.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, ApplicationProtocol = "smb2.write.request" } },
        "R951" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 443, ProcessId = 310, ProcessName = "teams.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, TlsVersion = "TLS1.3", Sni = "service.example.net" }, new TrafficRecord { Source = "10.1.1.10", Destination = "9.9.9.9", SourcePort = 51000, DestinationPort = 445, ProcessId = 310, ProcessName = "teams.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R952" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "wscript.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, ApplicationProtocol = "HTTP", HttpMethod = "GET", HttpUri = "/script.vbs", HttpHost = "service.example.net" }, new TrafficRecord { Source = "10.1.1.10", Destination = "9.9.9.9", SourcePort = 51000, DestinationPort = 443, ProcessId = 310, ProcessName = "wscript.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, TlsVersion = "TLS1.3", Sni = "service.example.net" } },
        "R953" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "cscript.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, ApplicationProtocol = "HTTP", HttpMethod = "GET", HttpUri = "/script.js", HttpHost = "service.example.net" }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 135, ProcessId = 310, ProcessName = "cscript.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R954" => new[] { new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 80, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, ApplicationProtocol = "HTTP", HttpMethod = "GET", HttpUri = "/index.php", HttpHost = "service.example.net" }, new TrafficRecord { Source = "10.1.2.45", Destination = "9.9.9.9", SourcePort = 51000, DestinationPort = 4444, ProcessId = 310, ProcessName = "bash", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R955" => new[] { new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 80, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, ApplicationProtocol = "HTTP", HttpMethod = "POST", HttpUri = "/service.aspx", HttpHost = "service.example.net" }, new TrafficRecord { Source = "10.1.2.45", Destination = "9.9.9.9", SourcePort = 51000, DestinationPort = 5985, ProcessId = 310, ProcessName = "w3wp.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R956" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 135, ProcessId = 310, ProcessName = "net.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 389, ProcessId = 310, ProcessName = "net.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R957" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 135, ProcessId = 310, ProcessName = "wmic.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 445, ProcessId = 310, ProcessName = "wmic.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R958" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "curl", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, ApplicationProtocol = "HTTP", HttpMethod = "GET", HttpUri = "/generate_204", HttpHost = "connectivitycheck.gstatic.com" }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 902, ProcessId = 310, ProcessName = "curl", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R959" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 53, ProcessId = 310, ProcessName = "powershell.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 443, ProcessId = 310, ProcessName = "powershell.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, TlsVersion = "TLS1.3", Sni = "service.example.net" } },
        "R960" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 22, ProcessId = 310, ProcessName = "ssh", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700 }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 22, ProcessId = 310, ProcessName = "ssh", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700 }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 22, ProcessId = 310, ProcessName = "ssh", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700 }, new TrafficRecord { Source = "10.1.1.10", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 22, ProcessId = 310, ProcessName = "ssh", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700 } },
        "R961" => new[] { new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 3128, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.2.45", Destination = "10.1.3.77", SourcePort = 51000, DestinationPort = 502, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        "R962" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 53, ProcessId = 310, ProcessName = "python", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsUdp = true, Protocol = "UDP", Length = 128, L4Len = 100, ApplicationProtocol = "DNS", DnsQname = "update.example.net", DnsQtype = "A", DnsRcode = "NOERROR" }, new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.1.10", SourcePort = 53, DestinationPort = 51000, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsUdp = true, Protocol = "UDP", Length = 128, L4Len = 100, ApplicationProtocol = "DNS", DnsQname = "update.example.net", DnsQtype = "A", DnsRcode = "NOERROR", DnsIsResponse = true, DnsTtl = 15, DnsAnswers = "1.1.1.1" }, new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 53, ProcessId = 310, ProcessName = "python", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsUdp = true, Protocol = "UDP", Length = 128, L4Len = 100, ApplicationProtocol = "DNS", DnsQname = "update.example.net", DnsQtype = "A", DnsRcode = "NOERROR" }, new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.1.10", SourcePort = 53, DestinationPort = 51000, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsUdp = true, Protocol = "UDP", Length = 128, L4Len = 100, ApplicationProtocol = "DNS", DnsQname = "update.example.net", DnsQtype = "A", DnsRcode = "NOERROR", DnsIsResponse = true, DnsTtl = 15, DnsAnswers = "9.9.9.9" }, new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 53, ProcessId = 310, ProcessName = "python", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsUdp = true, Protocol = "UDP", Length = 128, L4Len = 100, ApplicationProtocol = "DNS", DnsQname = "update.example.net", DnsQtype = "A", DnsRcode = "NOERROR" }, new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.1.10", SourcePort = 53, DestinationPort = 51000, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsUdp = true, Protocol = "UDP", Length = 128, L4Len = 100, ApplicationProtocol = "DNS", DnsQname = "update.example.net", DnsQtype = "A", DnsRcode = "NOERROR", DnsIsResponse = true, DnsTtl = 15, DnsAnswers = "208.67.222.222" } },
        "R963" => new[] { new TrafficRecord { Source = "8.8.8.8", Destination = "10.1.2.45", SourcePort = 51000, DestinationPort = 22, ProcessId = 0, ProcessName = null, IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 }, new TrafficRecord { Source = "10.1.2.45", Destination = "9.9.9.9", SourcePort = 51000, DestinationPort = 443, ProcessId = 310, ProcessName = "sshd", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, TlsVersion = "TLS1.3", Sni = "service.example.net" } },
        "R964" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 8443, ProcessId = 310, ProcessName = "openssl", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, TlsVersion = "TLS1.3", Sni = "service.example.net" }, new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 443, ProcessId = 310, ProcessName = "openssl", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, TlsVersion = "TLS1.3", Sni = "service.example.net" } },
        "R965" => new[] { new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 80, ProcessId = 310, ProcessName = "spoolsv.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x18, Length = 740, L4Len = 700, ApplicationProtocol = "HTTP", HttpMethod = "GET", HttpUri = "/driver.dll", HttpHost = "service.example.net" }, new TrafficRecord { Source = "10.1.1.10", Destination = "8.8.8.8", SourcePort = 51000, DestinationPort = 445, ProcessId = 310, ProcessName = "spoolsv.exe", IpVersion = 4, Id = Guid.NewGuid(), Info = "RAW-INFO-PRIVATE-MARKER", IsTcp = true, Protocol = "TCP", TcpFlags = 0x02, Length = 40, L4Len = 0 } },
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };
    private static RuleEvaluationContext At(TrafficRecord r, double seconds)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));
    private static int Step(string id) => id == "R960" ? 10 : 3;
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
    public async Task WrongFinalPortNearMiss(string id)
    {
        var rule = Rule(id); var records = Packets(id);
        for (var i = 0; i < records.Length; i++)
        {
            var r = records[i];
            if (i == records.Length - 1) { r.DestinationPort = 65000; r.SourcePort = 65001; }
            Assert.False((await rule.EvaluateAsync(At(r, i * Step(id)))).Matched);
        }
    }
    [Theory, MemberData(nameof(Cases))]
    public async Task DuplicateReverseAndExpiry(string id)
    {
        var records = Packets(id); var rule = Rule(id);
        await rule.EvaluateAsync(At(records[0], 100));
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
    public async Task CooldownRecoveryAndIndependentInstances(string id)
    {
        var rule = Rule(id);
        Assert.True((await Trigger(rule, id, 0)).Matched);
        Assert.True((await Trigger(rule, id, 300)).Suppressed);
        Assert.True((await Trigger(rule, id, 950)).Matched);
        Assert.True((await Trigger(Rule(id), id, 0)).Matched);
    }
    [Fact]
    public async Task CorrelationRejectsUnrelatedPidAndHost()
    {
        foreach (var id in new[] { "R950", "R951", "R952", "R953", "R956", "R957", "R958", "R959", "R964", "R965" })
        {
            var rule = Rule(id); var records = Packets(id);
            await rule.EvaluateAsync(At(records[0], 0)); records[1].ProcessId++;
            Assert.False((await rule.EvaluateAsync(At(records[1], 3))).Matched);
        }
        foreach (var id in new[] { "R947", "R954", "R955", "R961", "R963" })
        {
            var rule = Rule(id); var records = Packets(id);
            await rule.EvaluateAsync(At(records[0], 0)); records[1].Source = "10.9.9.9";
            Assert.False((await rule.EvaluateAsync(At(records[1], 3))).Matched);
        }
        var tftp = Rule("R946"); var pair = Packets("R946");
        await tftp.EvaluateAsync(At(pair[0], 0)); pair[1].DestinationPort++;
        Assert.False((await tftp.EvaluateAsync(At(pair[1], 3))).Matched);
    }
    [Fact]
    public async Task ParserLabelCannotBeReplacedByRawInfo()
    {
        foreach (var id in new[] { "R948", "R949", "R950" })
        {
            var rule = Rule(id); var records = Packets(id);
            for (var i = 0; i < records.Length; i++)
            {
                if (records[i].ApplicationProtocol is "ftp.stor" or "smb2.write.request")
                { records[i].Info = records[i].ApplicationProtocol; records[i].ApplicationProtocol = null; }
                Assert.False((await rule.EvaluateAsync(At(records[i], i * 3))).Matched);
            }
        }
    }
    [Fact]
    public async Task DnsChurnNeedsDistinctAnswersAndMatchedQueries()
    {
        foreach (var variant in new[] { "same", "name", "ttl", "port" })
        {
            var rule = Rule("R962"); var records = Packets("R962");
            for (var i = 0; i < records.Length; i++)
            {
                var r = records[i];
                if (r.DnsIsResponse)
                {
                    if (variant == "same") r.DnsAnswers = "1.1.1.1";
                    if (variant == "name") r.DnsQname = "other.example.net";
                    if (variant == "ttl") r.DnsTtl = 600;
                    if (variant == "port") r.DestinationPort++;
                }
                Assert.False((await rule.EvaluateAsync(At(r, i * 3))).Matched);
            }
        }
    }
    [Fact]
    public async Task CadenceRequiresSpacingAndPrivatePeer()
    {
        var rule = Rule("R960"); var records = Packets("R960");
        for (var i = 0; i < records.Length; i++)
            Assert.False((await rule.EvaluateAsync(At(records[i], i))).Matched);
        rule = Rule("R960"); records = Packets("R960");
        for (var i = 0; i < records.Length; i++)
        { records[i].Destination = "8.8.8.8"; Assert.False((await rule.EvaluateAsync(At(records[i], i * 10))).Matched); }
    }
    [Fact]
    public async Task HttpResourceAndScopeNearMisses()
    {
        foreach (var id in new[] { "R950", "R952", "R953", "R954", "R955", "R958", "R965" })
        {
            var rule = Rule(id); var records = Packets(id);
            records[0].HttpUri = "/unrelated.txt";
            for (var i = 0; i < records.Length; i++)
                Assert.False((await rule.EvaluateAsync(At(records[i], i * 3))).Matched);
        }
        var r961 = Rule("R961"); var p = Packets("R961"); p[1].Destination = "10.1.2.46";
        await r961.EvaluateAsync(At(p[0], 0));
        Assert.False((await r961.EvaluateAsync(At(p[1], 3))).Matched);
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
