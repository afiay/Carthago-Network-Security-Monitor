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
public sealed class R656R665AdvancedAccuracyBatchTests
{
  private static readonly DateTime Origin=new(2026,11,3,22,0,0,DateTimeKind.Utc);
  private static IDetectionRule New(string id)=>id switch
  {
    "R656"=>new R656_OfficialGitRemoteProcessSmartHttpPushRequestRule(),
    "R657"=>new R657_ScriptAttributedPasteApiHttpPostRequestRule(),
    "R658"=>new R658_UniformIntervalOutboundProcessTcpPayloadSequenceRule(),
    "R659"=>new R659_PublicManagementPortTriadToPrivateDeviceRule(),
    "R660"=>new R660_EngineeringProcessDirectPublicDnsQueryRule(),
    "R661"=>new R661_ScriptHostExternalMailServiceTcpEgressRule(),
    "R662"=>new R662_IdeProcessVisualStudioDevTunnelTlsSniEgressRule(),
    "R663"=>new R663_ExternalFtpStorAppeRequestPairRule(),
    "R664"=>new R664_ScriptProcessLongEncodedHttpGetToIpLiteralRule(),
    "R665"=>new R665_ExplorerWebDavThenExternalSmbSynSequenceRule(),
    _=>throw new ArgumentOutOfRangeException(nameof(id))
  };
  private static RuleEvaluationContext At(TrafficRecord r,int sec=0)
    =>new(r,Sensitivity.Balanced,Origin.AddSeconds(sec));
  private static TrafficRecord Http(string method,string uri,string host,string process="git.exe",int pid=181)
    =>new(){
      Id=Guid.NewGuid(),Source="10.1.2.20",Destination="8.8.8.8",IpVersion=4,
      Protocol="TCP",IsTcp=true,SourcePort=50221,DestinationPort=80,
      L4Len=300,Length=350,ApplicationProtocol="HTTP",
      HttpMethod=method,HttpUri=uri,HttpHost=host,HttpUserAgent="git/2.42",
      ProcessName=process,ProcessId=pid
    };
  private static TrafficRecord Tcp(string process,int port=443,int length=1000)
    =>new(){
      Id=Guid.NewGuid(),Source="10.1.2.20",Destination="8.8.8.8",IpVersion=4,
      Protocol="TCP",IsTcp=true,SourcePort=50221,DestinationPort=port,
      L4Len=length,Length=length+40,ProcessName=process,ProcessId=181
    };
  private static TrafficRecord Dns(string process,string destination="8.8.8.8")
    =>new(){
      Id=Guid.NewGuid(),Source="10.1.2.20",Destination=destination,IpVersion=4,
      Protocol="UDP",IsUdp=true,SourcePort=53311,DestinationPort=53,
      L4Len=70,Length=110,DnsQname="device.example.test",DnsQtype="A",
      ApplicationService="DNS",ProcessName=process,ProcessId=181
    };
  private static TrafficRecord InboundPort(int port,string protocol="TCP")
    =>new(){
      Id=Guid.NewGuid(),Source="8.8.8.8",Destination="10.1.2.40",IpVersion=4,
      Protocol=protocol,IsTcp=protocol=="TCP",IsUdp=protocol=="UDP",
      SourcePort=54000,DestinationPort=port,L4Len=60,Length=100
    };
  [Fact] public async Task GitPush_Requires_Exact_GitProcess_Host_And_SmartHttp_Route()
  {
    var yes=Http("POST","/owner/repo.git/git-receive-pack","github.com");
    Assert.True((await New("R656").EvaluateAsync(At(yes))).Matched);
    Assert.False((await New("R656").EvaluateAsync(At(Http("POST","/owner/repo.git/git-upload-pack","github.com")))).Matched);
    Assert.False((await New("R656").EvaluateAsync(At(Http("POST","/owner/repo.git/git-receive-pack","github.com.evil.test")))).Matched);
    Assert.False((await New("R656").EvaluateAsync(At(Http("POST","/owner/repo.git/git-receive-pack","github.com","chrome.exe")))).Matched);
  }
  [Fact] public async Task PasteService_Requires_Local_Script_And_Exact_Post_Route()
  {
    Assert.True((await New("R657").EvaluateAsync(At(Http("POST","/api/api_post.php","pastebin.com","curl.exe")))).Matched);
    Assert.False((await New("R657").EvaluateAsync(At(Http("GET","/api/api_post.php","pastebin.com","curl.exe")))).Matched);
    Assert.False((await New("R657").EvaluateAsync(At(Http("POST","/api/api_post.php","pastebin.com","chrome.exe")))).Matched);
    Assert.False((await New("R657").EvaluateAsync(At(Http("POST","/api/api_post.php","pastebin.com.evil.test","curl.exe")))).Matched);
  }
  [Fact] public async Task UniformTcp_RequiresFourTimedSegmentsAndNoHttp()
  {
    var rule=New("R658");
    Assert.False((await rule.EvaluateAsync(At(Tcp("tools.exe"),0))).Matched);
    Assert.False((await rule.EvaluateAsync(At(Tcp("tools.exe",length:1008),15))).Matched);
    Assert.False((await rule.EvaluateAsync(At(Tcp("tools.exe",length:1004),30))).Matched);
    Assert.True((await rule.EvaluateAsync(At(Tcp("tools.exe",length:1002),45))).Matched);
    var other=New("R658");
    Assert.False((await other.EvaluateAsync(At(Tcp("tools.exe"),0))).Matched);
    Assert.False((await other.EvaluateAsync(At(Tcp("tools.exe"),1))).Matched);
    var bad=Tcp("tools.exe");bad.HttpMethod="POST";
    Assert.False((await other.EvaluateAsync(At(bad,16))).Matched);
  }
  [Fact] public async Task ManagementProbe_RequiresSnmpNetconfAndHttpsServicePorts()
  {
    var rule=New("R659");
    Assert.False((await rule.EvaluateAsync(At(InboundPort(161,"UDP"),0))).Matched);
    Assert.False((await rule.EvaluateAsync(At(InboundPort(830),1))).Matched);
    Assert.True((await rule.EvaluateAsync(At(InboundPort(443),2))).Matched);
    var another=New("R659");
    Assert.False((await another.EvaluateAsync(At(InboundPort(161,"UDP"),0))).Matched);
    Assert.False((await another.EvaluateAsync(At(InboundPort(830),1))).Matched);
    Assert.False((await another.EvaluateAsync(At(InboundPort(830),2))).Matched);
  }
  [Fact] public async Task EngineeringDns_RequiresParsedQueryPublicResolverAndProcess()
  {
    Assert.True((await New("R660").EvaluateAsync(At(Dns("tia.exe")))).Matched);
    Assert.False((await New("R660").EvaluateAsync(At(Dns("chrome.exe")))).Matched);
    Assert.False((await New("R660").EvaluateAsync(At(Dns("tia.exe","10.1.2.53")))).Matched);
    var noPid=Dns("tia.exe");noPid.ProcessId=0;
    Assert.False((await New("R660").EvaluateAsync(At(noPid))).Matched);
    var answer=Dns("tia.exe");answer.DnsIsResponse=true;
    Assert.False((await New("R660").EvaluateAsync(At(answer))).Matched);
  }
  [Fact] public async Task ScriptMail_RequiresPublicEndpointMailPortAndExactProcess()
  {
    Assert.True((await New("R661").EvaluateAsync(At(Tcp("powershell.exe",587)))).Matched);
    Assert.False((await New("R661").EvaluateAsync(At(Tcp("chrome.exe",587)))).Matched);
    Assert.False((await New("R661").EvaluateAsync(At(Tcp("powershell.exe",80)))).Matched);
    var inside=Tcp("powershell.exe",587);inside.Destination="10.1.2.30";
    Assert.False((await New("R661").EvaluateAsync(At(inside))).Matched);
  }
  [Fact] public async Task DevTunnel_RequiresIdeProcessAndExactSniRoot()
  {
    var good=Tcp("code.exe");good.TlsVersion="TLS1.3";good.Sni="abc.devtunnels.ms";
    Assert.True((await New("R662").EvaluateAsync(At(good))).Matched);
    var fake=Tcp("code.exe");fake.TlsVersion="TLS1.3";fake.Sni="abc.devtunnels.ms.evil.test";
    Assert.False((await New("R662").EvaluateAsync(At(fake))).Matched);
    var chrome=Tcp("chrome.exe");chrome.TlsVersion="TLS1.3";chrome.Sni="abc.devtunnels.ms";
    Assert.False((await New("R662").EvaluateAsync(At(chrome))).Matched);
  }
  [Fact] public async Task Ftp_RequestPair_RequiresTwoDistinctOperationTypes()
  {
    var rule=New("R663");
    TrafficRecord Ftp(string op){var r=Tcp("winscp.exe",21,60);r.ApplicationProtocol=op;return r;}
    Assert.False((await rule.EvaluateAsync(At(Ftp("ftp.stor")))).Matched);
    Assert.False((await rule.EvaluateAsync(At(Ftp("ftp.stor"),1))).Matched);
    Assert.True((await rule.EvaluateAsync(At(Ftp("ftp.appe"),2))).Matched);
    Assert.False((await New("R663").EvaluateAsync(At(Ftp("ftp.list")))).Matched);
  }
  [Fact] public async Task EncodedGet_RequiresScriptPidIpHostAndLongUrlSafeData()
  {
    var data=new string('A',55)+new string('8',14)+"AbcdEF";
    var yes=Http("GET","/api?data="+data,"8.8.8.8","powershell.exe");
    Assert.True((await New("R664").EvaluateAsync(At(yes))).Matched);
    Assert.False((await New("R664").EvaluateAsync(At(Http("GET","/api?data="+data,"github.com","powershell.exe")))).Matched);
    Assert.False((await New("R664").EvaluateAsync(At(Http("GET","/api?data="+data,"8.8.8.8","chrome.exe")))).Matched);
    Assert.False((await New("R664").EvaluateAsync(At(Http("GET","/api?data=abc","8.8.8.8","powershell.exe")))).Matched);
  }
  [Fact] public async Task WebdavFollowedBySmbSynRequiresOrderedSameProcessAndDestination()
  {
    var rule=New("R665");
    var start=Http("GET","/remote.php/dav/files/user","8.8.8.8","explorer.exe");
    var after=Tcp("explorer.exe",445,0);after.TcpFlags=0x02;
    Assert.False((await rule.EvaluateAsync(At(start,0))).Matched);
    Assert.True((await rule.EvaluateAsync(At(after,1))).Matched);
    var isolated=New("R665");
    Assert.False((await isolated.EvaluateAsync(At(after,0))).Matched);
    Assert.False((await isolated.EvaluateAsync(At(start,1))).Matched);
    var different=Tcp("explorer.exe",445,0);different.TcpFlags=0x02;different.ProcessId=9000;
    Assert.False((await isolated.EvaluateAsync(At(different,2))).Matched);
  }
  [Fact] public async Task WrongParserInfoOnlyDuplicateAndCooldownCannotCreateExtraEvents()
  {
    var rule=New("R656");var record=Http("POST","/a/git-receive-pack","github.com");
    Assert.True((await rule.EvaluateAsync(At(record,10))).Matched);
    Assert.False((await rule.EvaluateAsync(At(record,11))).Matched);
    var earlier=Http("POST","/a/git-receive-pack","github.com");
    Assert.False((await rule.EvaluateAsync(At(earlier,9))).Matched);
    var another=Http("POST","/a/git-receive-pack","github.com");
    var suppressed=await rule.EvaluateAsync(At(another,12));
    Assert.True(suppressed.Suppressed);Assert.Empty(suppressed.Events);
    var forged=Http("POST","/safe","github.com");forged.Info="/a/git-receive-pack";
    Assert.False((await New("R656").EvaluateAsync(At(forged))).Matched);
    var wrong=Http("POST","/a/git-receive-pack","github.com");wrong.ApplicationProtocol="TLS";
    Assert.False((await New("R656").EvaluateAsync(At(wrong))).Matched);
  }
  [Fact] public async Task EvidenceRemainsOutcomeScopedAndDoesNotIncludeRawEncodedUri()
  {
    var data=new string('A',55)+new string('8',14)+"AbcdEF";
    var r=Http("GET","/api?data="+data,"8.8.8.8","powershell.exe");
    var evt=Assert.Single((await New("R664").EvaluateAsync(At(r))).Events);
    var json=JsonSerializer.Serialize(evt);
    Assert.DoesNotContain(data,json);Assert.Contains("encoded_http_get_request_only",json);
  }
  [Theory]
  [InlineData("R656")]
  [InlineData("R657")]
  [InlineData("R658")]
  [InlineData("R659")]
  [InlineData("R660")]
  [InlineData("R661")]
  [InlineData("R662")]
  [InlineData("R663")]
  [InlineData("R664")]
  [InlineData("R665")]
  public void RegisteredOnceAsSeparateCandidateShadowRule(string id)
  {
    var all=RuleRegistry.CreateDefaultRules();
    var rule=Assert.Single(all.Where(x=>x.Descriptor.RuleId==id));
    var precise=Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(rule);
    Assert.Equal(RulePrecisionMaturity.Candidate,precise.PrecisionProfile.Maturity);
    Assert.Equal(RuleRuntimeMode.Shadow,precise.PrecisionProfile.DefaultMode);
  }
}
