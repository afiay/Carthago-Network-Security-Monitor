// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed.
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

public sealed class R696R705AdvancedAccuracyBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 4, 11, 0, 0, DateTimeKind.Utc);

    private static IDetectionRule Rule(string id) => id switch
    {
        "R696" => new R696_BitsadminFileSharingServiceContactRule(),
        "R697" => new R697_CertutilFileSharingServiceContactRule(),
        "R698" => new R698_PowerShellFileSharingServiceContactRule(),
        "R699" => new R699_OfficeProcessSuspiciousExtensionHttpGetRule(),
        "R700" => new R700_Rundll32ExternalWebDavRequestRule(),
        "R701" => new R701_NetExeExternalWebDavRequestRule(),
        "R702" => new R702_OtServiceProtocolClassificationMismatchRule(),
        "R703" => new R703_ScriptProcessRepeatedPublicUdpPayloadBurstRule(),
        "R704" => new R704_UnattributedInternalRelaySynSequenceRule(),
        "R705" => new R705_UnattributedPublicBridgeSynSequenceRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    private static TrafficRecord Http(string process, string host="gofile.io", string uri="/payload.exe", string method="GET")
        => new()
        {
            Id=Guid.NewGuid(), Source="10.1.2.20", Destination="8.8.8.8", IpVersion=4,
            Protocol="TCP", IsTcp=true, SourcePort=52001, DestinationPort=80,
            L4Len=240, Length=280, ApplicationProtocol="HTTP",
            HttpMethod=method, HttpUri=uri, HttpHost=host, HttpUserAgent="Tool/1.0",
            ProcessName=process, ProcessId=4100
        };

    private static TrafficRecord Dav(string process, string method="PROPFIND")
        => new()
        {
            Id=Guid.NewGuid(), Source="10.1.2.20", Destination="8.8.8.8", IpVersion=4,
            Protocol="TCP", IsTcp=true, SourcePort=52002, DestinationPort=80,
            L4Len=120, Length=160, ApplicationProtocol="HTTP",
            HttpMethod=method, HttpUri="/webdav/share", HttpHost="dav.example",
            HttpRequestHeaders="Host: dav.example", ProcessName=process, ProcessId=4100
        };

    private static TrafficRecord Syn(string source, string destination, int destinationPort, int processId=0, string? processName=null)
        => new()
        {
            Id=Guid.NewGuid(), Source=source, Destination=destination, IpVersion=4,
            Protocol="TCP", IsTcp=true, SourcePort=53000, DestinationPort=destinationPort,
            TcpFlags=0x02, L4Len=0, Length=40, ProcessId=processId, ProcessName=processName
        };

    [Theory]
    [InlineData("R696","bitsadmin.exe")]
    [InlineData("R697","certutil.exe")]
    [InlineData("R698","powershell.exe")]
    public async Task FileSharingContactRequiresExactProcessAndProviderBoundary(string id,string process)
    {
        Assert.True((await Rule(id).EvaluateAsync(At(Http(process)))).Matched);
        Assert.False((await Rule(id).EvaluateAsync(At(Http("chrome.exe")))).Matched);
        Assert.False((await Rule(id).EvaluateAsync(At(Http(process,"gofile.io.evil.test")))).Matched);
        Assert.False((await Rule(id).EvaluateAsync(At(Http(process,method:"POST")))).Matched);
        var inside=Http(process);inside.Destination="10.1.2.40";
        Assert.False((await Rule(id).EvaluateAsync(At(inside))).Matched);
        var noPid=Http(process);noPid.ProcessId=0;
        Assert.False((await Rule(id).EvaluateAsync(At(noPid))).Matched);
    }

    [Fact]
    public async Task OfficeDownloadShapeRequiresOfficeProcessAndSuspiciousExtension()
    {
        Assert.True((await Rule("R699").EvaluateAsync(At(Http("winword.exe","files.example","/docs/update.dll")))).Matched);
        Assert.False((await Rule("R699").EvaluateAsync(At(Http("winword.exe","files.example","/docs/report.pdf")))).Matched);
        Assert.False((await Rule("R699").EvaluateAsync(At(Http("chrome.exe","files.example","/docs/update.dll")))).Matched);
        Assert.False((await Rule("R699").EvaluateAsync(At(Http("winword.exe","files.example","/docs/update.dll","POST")))).Matched);
    }

    [Theory]
    [InlineData("R700","rundll32.exe")]
    [InlineData("R701","net.exe")]
    public async Task ExternalWebDavRequiresExactUtilityAndDavMethod(string id,string process)
    {
        Assert.True((await Rule(id).EvaluateAsync(At(Dav(process)))).Matched);
        Assert.False((await Rule(id).EvaluateAsync(At(Dav("chrome.exe")))).Matched);
        Assert.False((await Rule(id).EvaluateAsync(At(Dav(process,"GET")))).Matched);
        var internalPeer=Dav(process);internalPeer.Destination="10.1.2.40";
        Assert.False((await Rule(id).EvaluateAsync(At(internalPeer))).Matched);
    }

    [Fact]
    public async Task OtProtocolMismatchRequiresKnownDifferentParserAndExcludesNormalProtocol()
    {
        TrafficRecord Ot(int port,string app)=>new()
        {
            Id=Guid.NewGuid(),Source="8.8.8.8",Destination="10.1.2.40",IpVersion=4,
            Protocol="TCP",IsTcp=true,SourcePort=54000,DestinationPort=port,
            L4Len=80,Length=120,ApplicationProtocol=app
        };
        Assert.True((await Rule("R702").EvaluateAsync(At(Ot(102,"HTTP")))).Matched);
        Assert.True((await Rule("R702").EvaluateAsync(At(Ot(44818,"TLS")))).Matched);
        Assert.False((await Rule("R702").EvaluateAsync(At(Ot(102,"s7comm")))).Matched);
        Assert.False((await Rule("R702").EvaluateAsync(At(Ot(44818,"ethernetip.listidentity")))).Matched);
        Assert.False((await Rule("R702").EvaluateAsync(At(Ot(502,"HTTP")))).Matched);
        var unknown=Ot(102,"HTTP");unknown.ApplicationProtocol=null;
        Assert.False((await Rule("R702").EvaluateAsync(At(unknown))).Matched);
    }

    [Fact]
    public async Task UdpBurstNeedsFivePacketsSameScriptProcessAndPeer()
    {
        TrafficRecord Udp(string process="python.exe",string destination="8.8.8.8",int port=4444)
            =>new()
            {
                Id=Guid.NewGuid(),Source="10.1.2.20",Destination=destination,IpVersion=4,
                Protocol="UDP",IsUdp=true,SourcePort=53001,DestinationPort=port,
                L4Len=220,Length=260,ProcessName=process,ProcessId=4100
            };
        var rule=Rule("R703");
        for(var i=0;i<4;i++)Assert.False((await rule.EvaluateAsync(At(Udp(),i))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Udp(),4))).Matched);
        Assert.False((await Rule("R703").EvaluateAsync(At(Udp("chrome.exe")))).Matched);
        Assert.False((await Rule("R703").EvaluateAsync(At(Udp(destination:"10.1.2.30")))).Matched);
        Assert.False((await Rule("R703").EvaluateAsync(At(Udp(port:5353)))).Matched);
    }

    [Fact]
    public async Task InternalRelayRequiresNoProcessAndDifferentInternalPeers()
    {
        var rule=Rule("R704");
        var inbound=Syn("10.1.2.10","10.1.2.20",9000);
        var outbound=Syn("10.1.2.20","10.1.2.30",445);
        Assert.False((await rule.EvaluateAsync(At(inbound,0))).Matched);
        Assert.True((await rule.EvaluateAsync(At(outbound,1))).Matched);

        var attributed=Rule("R704");
        var first=Syn("10.1.2.10","10.1.2.20",9000,4200,"socat.exe");
        Assert.False((await attributed.EvaluateAsync(At(first,0))).Matched);

        var samePeer=Rule("R704");
        Assert.False((await samePeer.EvaluateAsync(At(inbound,0))).Matched);
        Assert.False((await samePeer.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.10",445),1))).Matched);
    }

    [Fact]
    public async Task PublicBridgeRequiresNoProcessAndDifferentPublicPeers()
    {
        var rule=Rule("R705");
        var inbound=Syn("8.8.8.8","10.1.2.20",9000);
        var outbound=Syn("10.1.2.20","9.9.9.9",443);
        Assert.False((await rule.EvaluateAsync(At(inbound,0))).Matched);
        Assert.True((await rule.EvaluateAsync(At(outbound,1))).Matched);

        var processRule=Rule("R705");
        var attributed=Syn("8.8.8.8","10.1.2.20",9000,4100,"socat.exe");
        Assert.False((await processRule.EvaluateAsync(At(attributed,0))).Matched);

        var samePeer=Rule("R705");
        Assert.False((await samePeer.EvaluateAsync(At(inbound,0))).Matched);
        Assert.False((await samePeer.EvaluateAsync(At(Syn("10.1.2.20","8.8.8.8",443),1))).Matched);
    }

    [Fact]
    public async Task ReplayCooldownAndEvidenceRemainOutcomeScoped()
    {
        var rule=Rule("R696");
        var record=Http("bitsadmin.exe");
        var evt=Assert.Single((await rule.EvaluateAsync(At(record,10))).Events);
        var json=JsonSerializer.Serialize(evt);
        Assert.Contains("file_sharing_contact_only_unknown",json);
        Assert.DoesNotContain("/payload.exe",json);
        Assert.False((await rule.EvaluateAsync(At(record,11))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Http("bitsadmin.exe"),9))).Matched);
        var suppressed=await rule.EvaluateAsync(At(Http("bitsadmin.exe"),12));
        Assert.True(suppressed.Suppressed);Assert.Empty(suppressed.Events);
        Assert.True((await rule.EvaluateAsync(At(Http("bitsadmin.exe"),611))).Matched);
    }

    [Theory]
    [InlineData("R696")]
    [InlineData("R697")]
    [InlineData("R698")]
    [InlineData("R699")]
    [InlineData("R700")]
    [InlineData("R701")]
    [InlineData("R702")]
    [InlineData("R703")]
    [InlineData("R704")]
    [InlineData("R705")]
    public void RegistryContainsExactlyOneCandidateShadow(string id)
    {
        var found=Assert.Single(RuleRegistry.CreateDefaultRules().Where(x=>x.Descriptor.RuleId==id));
        var precision=Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(found);
        Assert.Equal(RulePrecisionMaturity.Candidate,precision.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,precision.PrecisionProfile.DefaultMode);
    }
}
