// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed; no build invoked.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R626R635AdvancedAccuracyBatchTests
{
  private static readonly DateTime Epoch=new(2026,11,3,20,0,0,DateTimeKind.Utc);
  private static readonly string[] Ids={"R626","R627","R628","R629","R630","R631","R632","R633","R634","R635"};
  private static IDetectionRule Rule(string id)=>id switch
  {
    "R626"=>new R626_WordPressWp2shellPluginRequestRule(),
    "R627"=>new R627_WebLogicKeystoreJspRequestRule(),
    "R628"=>new R628_ExchangeProxyTokenRulesEditorRequestRule(),
    "R629"=>new R629_HybridConnectionManagerServiceBusDnsRule(),
    "R630"=>new R630_PowerShellOutboundPublicWinRmRule(),
    "R631"=>new R631_CommandInterpreterOutboundRdpRule(),
    "R632"=>new R632_SvchostRdpLoopbackFlowRule(),
    "R633"=>new R633_CertutilExternalServiceTcpRule(),
    "R634"=>new R634_WindowsScriptHostNonHttpOutboundTcpRule(),
    "R635"=>new R635_NonBrowserProcessDeadDropHostRule(),
    _=>throw new ArgumentOutOfRangeException(nameof(id))
  };
  private static RuleEvaluationContext At(TrafficRecord r,int sec=0)=>new(r,Sensitivity.Balanced,Epoch.AddSeconds(sec));
  private static TrafficRecord Http(string method,string uri)=>new()
  {
    Id=Guid.NewGuid(),Source="10.1.1.20",Destination="10.1.1.30",IpVersion=4,
    Protocol="TCP",IsTcp=true,SourcePort=50000,DestinationPort=8080,
    L4Len=400,Length=512,ApplicationProtocol="HTTP",HttpMethod=method,
    HttpUri=uri,HttpUserAgent="curl/8.0",HttpHost="web.lab"
  };
  private static TrafficRecord Dns(string name,string process)=>new()
  {
    Id=Guid.NewGuid(),Source="10.1.1.20",Destination="10.1.1.53",IpVersion=4,
    Protocol="UDP",IsUdp=true,SourcePort=51011,DestinationPort=53,
    L4Len=70,Length=112,ApplicationService="DNS",DnsQname=name,DnsQtype="A",
    ProcessId=4001,ProcessName=process
  };
  private static TrafficRecord Process(string process,int port)=>new()
  {
    Id=Guid.NewGuid(),Source="10.1.1.20",Destination="8.8.8.8",IpVersion=4,
    Protocol="TCP",IsTcp=true,SourcePort=51012,DestinationPort=port,
    L4Len=100,Length=140,ProcessId=4001,ProcessName=process
  };
  private static TrafficRecord Loopback(string process,int port)=>new()
  {
    Id=Guid.NewGuid(),Source="127.0.0.1",Destination="127.0.0.1",IpVersion=4,
    Protocol="TCP",IsTcp=true,SourcePort=port,DestinationPort=51014,
    L4Len=40,Length=80,ProcessId=4001,ProcessName=process
  };
  public static IEnumerable<object[]> HttpCases()
  {
    yield return new object[]{"R626","GET","/wp-content/plugins/wp2shell_abc/shell.php?cmd=id","/wp-content/plugins/normal/shell.php?cmd=id"};
    yield return new object[]{"R627","GET","/config/keystore/eval.jsp?i=1","/config/keystore/readme.txt?i=1"};
    yield return new object[]{"R628","POST","/ecp/RulesEditor/InboxRules.svc/NewObject?name=rule1","/ecp/RulesEditor/InboxRules.svc/GetObject?name=rule1"};
  }
  public static IEnumerable<object[]> ProcessCases()
  {
    yield return new object[]{"R630","powershell.exe",5985,8080};
    yield return new object[]{"R631","cmd.exe",3389,445};
    yield return new object[]{"R633","certutil.exe",443,53};
    yield return new object[]{"R634","wscript.exe",4444,80};
    yield return new object[]{"R635","rundll32.exe",443,443};
  }
  [Theory,MemberData(nameof(HttpCases))]
  public async Task ExactWebRequestMatchesAndNearMissDoesNot(string id,string method,string hit,string miss)
  {
    var pos=await Rule(id).EvaluateAsync(At(Http(method,hit)));
    Assert.True(pos.Matched);Assert.Equal(id,Assert.Single(pos.Events).RuleId);
    Assert.False((await Rule(id).EvaluateAsync(At(Http(method,miss)))).Matched);
  }
  [Theory,MemberData(nameof(HttpCases))]
  public async Task WebRequestWrongMethodMalformedAndInfoOnlyReject(string id,string method,string hit,string miss)
  {
    var rule=Rule(id);
    Assert.False((await rule.EvaluateAsync(At(Http(method,miss),-1))).Matched);
    var wrong=Http("DELETE",hit);
    var info=Http(method,"/safe");info.Info=hit;
    var tls=Http(method,hit);tls.TlsVersion="TLS1.3";
    var dns=Http(method,hit);dns.DnsQname="foreign.example";
    var missing=Http(method,hit);missing.ApplicationProtocol=null;
    Assert.False((await rule.EvaluateAsync(At(wrong))).Matched);
    Assert.False((await rule.EvaluateAsync(At(info,1))).Matched);
    Assert.False((await rule.EvaluateAsync(At(tls,2))).Matched);
    Assert.False((await rule.EvaluateAsync(At(dns,3))).Matched);
    Assert.False((await rule.EvaluateAsync(At(missing,4))).Matched);
  }
  [Theory,MemberData(nameof(HttpCases))]
  public async Task WebRequestDuplicateIdCooldownAndNoRawUriEvidence(string id,string method,string hit,string miss)
  {
    var rule=Rule(id);
    Assert.False((await rule.EvaluateAsync(At(Http(method,miss),8))).Matched);
    var a=Http(method,hit);
    var e=Assert.Single((await rule.EvaluateAsync(At(a,10))).Events);
    var data=JsonSerializer.Serialize(e);
    Assert.DoesNotContain(hit,data);Assert.Contains("request_only_unknown",data);
    Assert.False((await rule.EvaluateAsync(At(a,11))).Matched);
    Assert.False((await rule.EvaluateAsync(At(Http(method,hit),9))).Matched);
    var suppressed=await rule.EvaluateAsync(At(Http(method,hit),12));
    Assert.True(suppressed.Suppressed);Assert.Empty(suppressed.Events);
    Assert.True((await rule.EvaluateAsync(At(Http(method,hit),611))).Matched);
  }
  [Fact]
  public async Task HybridDnsNeedsRealProcessAndExactDomainBoundary()
  {
    var yes=await Rule("R629").EvaluateAsync(At(Dns("sb.servicebus.windows.net","HybridConnectionManager.exe")));
    Assert.True(yes.Matched);
    Assert.False((await Rule("R629").EvaluateAsync(At(Dns("sb.servicebus.windows.net.evil.test","HybridConnectionManager.exe")))).Matched);
    Assert.False((await Rule("R629").EvaluateAsync(At(Dns("sb.servicebus.windows.net","powershell.exe")))).Matched);
    var absent=Dns("sb.servicebus.windows.net","HybridConnectionManager.exe");absent.ProcessId=0;
    Assert.False((await Rule("R629").EvaluateAsync(At(absent))).Matched);
  }
  [Fact]
  public async Task HybridDnsRejectsResponsesWrongPortAndForgedInfo()
  {
    var rule=Rule("R629");
    var answer=Dns("sb.servicebus.windows.net","HybridConnectionManager.exe");answer.DnsIsResponse=true;
    var port=Dns("sb.servicebus.windows.net","HybridConnectionManager.exe");port.DestinationPort=5353;
    var spoof=Dns("test.example","HybridConnectionManager.exe");spoof.Info="sb.servicebus.windows.net";
    var tls=Dns("sb.servicebus.windows.net","HybridConnectionManager.exe");tls.TlsVersion="TLS1.3";
    Assert.False((await rule.EvaluateAsync(At(answer))).Matched);
    Assert.False((await rule.EvaluateAsync(At(port,1))).Matched);
    Assert.False((await rule.EvaluateAsync(At(spoof,2))).Matched);
    Assert.False((await rule.EvaluateAsync(At(tls,3))).Matched);
  }
  [Fact]
  public async Task HybridDnsRedactionCooldownAndReplayProtection()
  {
    var rule=Rule("R629");var a=Dns("sb.servicebus.windows.net","HybridConnectionManager.exe");
    var evt=Assert.Single((await rule.EvaluateAsync(At(a,10))).Events);
    var text=JsonSerializer.Serialize(evt);
    Assert.DoesNotContain("sb.servicebus.windows.net",text);
    Assert.Contains("dns_process_identity_unverified",text);
    Assert.False((await rule.EvaluateAsync(At(a,11))).Matched);
    Assert.True((await rule.EvaluateAsync(At(Dns("sb.servicebus.windows.net","HybridConnectionManager.exe"),12))).Suppressed);
    Assert.True((await rule.EvaluateAsync(At(Dns("sb.servicebus.windows.net","HybridConnectionManager.exe"),611))).Matched);
  }
  [Theory,MemberData(nameof(ProcessCases))]
  public async Task ProcessSpecificPublicFlowAndPortNearMiss(string id,string proc,int port,int wrong)
  {
    var sample=Process(proc,port);
    if(id=="R635"){sample.TlsVersion="TLS1.3";sample.Sni="www.youtube.com";}
    var found=await Rule(id).EvaluateAsync(At(sample));
    Assert.True(found.Matched);Assert.Equal(id,Assert.Single(found.Events).RuleId);
    var near=Process(proc,wrong);
    if(id=="R635"){near.TlsVersion="TLS1.3";near.Sni="www.microsoft.com";}
    Assert.False((await Rule(id).EvaluateAsync(At(near))).Matched);
  }
  [Theory,MemberData(nameof(ProcessCases))]
  public async Task ProcessFlowWrongPidInternalEndpointAndUdpReject(string id,string proc,int port,int wrong)
  {
    var rule=Rule(id);
    TrafficRecord Make(){var r=Process(proc,port);if(id=="R635"){r.TlsVersion="TLS1.3";r.Sni="www.youtube.com";}return r;}
    var near=Process(proc,wrong);if(id=="R635"){near.TlsVersion="TLS1.3";near.Sni="www.microsoft.com";}
    Assert.False((await rule.EvaluateAsync(At(near,-1))).Matched);
    var pid=Make();pid.ProcessId=0;
    var internalHost=Make();internalHost.Destination="10.1.2.12";
    var udp=Make();udp.IsTcp=false;udp.IsUdp=true;
    var wrongName=Make();wrongName.ProcessName="explorer.exe";
    Assert.False((await rule.EvaluateAsync(At(pid))).Matched);
    Assert.False((await rule.EvaluateAsync(At(internalHost,1))).Matched);
    Assert.False((await rule.EvaluateAsync(At(udp,2))).Matched);
    Assert.False((await rule.EvaluateAsync(At(wrongName,3))).Matched);
  }
  [Theory,MemberData(nameof(ProcessCases))]
  public async Task ProcessFlowCooldownReplayAndUnverifiedOutcome(string id,string proc,int port,int wrong)
  {
    var rule=Rule(id);
    TrafficRecord Make(){var r=Process(proc,port);if(id=="R635"){r.TlsVersion="TLS1.3";r.Sni="www.youtube.com";}return r;}
    var near=Process(proc,wrong);if(id=="R635"){near.TlsVersion="TLS1.3";near.Sni="www.microsoft.com";}
    Assert.False((await rule.EvaluateAsync(At(near,8))).Matched);
    var a=Make();var evt=Assert.Single((await rule.EvaluateAsync(At(a,10))).Events);
    var raw=JsonSerializer.Serialize(evt);
    Assert.Contains("process_flow_identity_unverified",raw);
    Assert.DoesNotContain("successful exploitation",raw,StringComparison.OrdinalIgnoreCase);
    Assert.False((await rule.EvaluateAsync(At(a,11))).Matched);
    Assert.False((await rule.EvaluateAsync(At(Make(),9))).Matched);
    var suppressed=await rule.EvaluateAsync(At(Make(),12));
    Assert.True(suppressed.Suppressed);Assert.Empty(suppressed.Events);
    Assert.True((await rule.EvaluateAsync(At(Make(),611))).Matched);
  }
  [Fact]
  public async Task LoopbackRdpMatchesOnlySvchostSourcePort3389()
  {
    Assert.True((await Rule("R632").EvaluateAsync(At(Loopback("svchost.exe",3389)))).Matched);
    Assert.False((await Rule("R632").EvaluateAsync(At(Loopback("svchost.exe",445)))).Matched);
    Assert.False((await Rule("R632").EvaluateAsync(At(Loopback("explorer.exe",3389)))).Matched);
    var external=Loopback("svchost.exe",3389);external.Destination="8.8.8.8";
    Assert.False((await Rule("R632").EvaluateAsync(At(external))).Matched);
    var absent=Loopback("svchost.exe",3389);absent.ProcessId=0;
    Assert.False((await Rule("R632").EvaluateAsync(At(absent))).Matched);
  }
  [Fact]
  public async Task LoopbackRdpReplayCooldownAndRedactedEvidence()
  {
    var rule=Rule("R632");var a=Loopback("svchost.exe",3389);
    var evt=Assert.Single((await rule.EvaluateAsync(At(a,10))).Events);
    var data=JsonSerializer.Serialize(evt);
    Assert.Contains("process_flow_identity_unverified",data);
    Assert.False((await rule.EvaluateAsync(At(a,11))).Matched);
    Assert.True((await rule.EvaluateAsync(At(Loopback("svchost.exe",3389),12))).Suppressed);
    Assert.True((await rule.EvaluateAsync(At(Loopback("svchost.exe",3389),611))).Matched);
  }
  [Fact]
  public void CatalogPreservesTenIndependentCandidateRules()
  {
    var all=RuleRegistry.CreateDefaultRules();
    foreach(var id in Ids)
    {
      var item=Assert.Single(all.Where(x=>x.Descriptor.RuleId==id));
      var precise=Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(item);
      Assert.Equal(RulePrecisionMaturity.Candidate,precise.PrecisionProfile.Maturity);
      Assert.Equal(RuleRuntimeMode.Shadow,precise.PrecisionProfile.DefaultMode);
    }
    Assert.Equal(Ids.Length,all.Count(r=>Ids.Contains(r.Descriptor.RuleId)));
  }
}
