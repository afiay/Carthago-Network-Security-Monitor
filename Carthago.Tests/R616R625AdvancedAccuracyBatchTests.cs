// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; authored xUnit only, never executed.
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
public sealed class R616R625AdvancedAccuracyBatchTests
{
  private static readonly DateTime Epoch=new(2026,11,3,20,0,0,DateTimeKind.Utc);
  private static readonly string[] Ids={"R616","R617","R618","R619","R620","R621","R622","R623","R624","R625"};
  private static IDetectionRule New(string id)=>id switch
  {
    "R616"=>new R616_ExchangeEcpVirtualDirectoryResetRequestRule(),
    "R617"=>new R617_SolarWindsSupernovaClazzRequestRule(),
    "R618"=>new R618_ExchangeProxyShellAutodiscoverBackendRequestRule(),
    "R619"=>new R619_EncodedJavaExpressionUriRequestRule(),
    "R620"=>new R620_LocaltoNetServiceDnsQueryRule(),
    "R621"=>new R621_HistoricalThreeCxDomainDnsQueryRule(),
    "R622"=>new R622_NotepadExternalTcpEgressRule(),
    "R623"=>new R623_DialerExternalTcpEgressRule(),
    "R624"=>new R624_AddInUtilExternalTcpEgressRule(),
    "R625"=>new R625_EquationEditorExternalTcpEgressRule(),
    _=>throw new ArgumentOutOfRangeException(nameof(id))
  };
  private static RuleEvaluationContext At(TrafficRecord r,int seconds=0)
    =>new(r,Sensitivity.Balanced,Epoch.AddSeconds(seconds));
  private static TrafficRecord Http(string method,string uri)=>new()
  {
    Id=Guid.NewGuid(),Source="10.4.1.20",Destination="10.4.1.30",IpVersion=4,
    Protocol="TCP",IsTcp=true,SourcePort=49001,DestinationPort=8080,
    L4Len=400,Length=512,ApplicationProtocol="HTTP",HttpMethod=method,
    HttpUri=uri,HttpUserAgent="curl/8.0",HttpHost="test.lab"
  };
  private static TrafficRecord Dns(string name)=>new()
  {
    Id=Guid.NewGuid(),Source="10.4.1.20",Destination="10.4.1.53",IpVersion=4,
    Protocol="UDP",IsUdp=true,SourcePort=53333,DestinationPort=53,
    L4Len=68,Length=110,ApplicationService="DNS",DnsQname=name,DnsQtype="A"
  };
  private static TrafficRecord Process(string name)=>new()
  {
    Id=Guid.NewGuid(),Source="10.4.1.20",Destination="8.8.8.8",IpVersion=4,
    Protocol="TCP",IsTcp=true,SourcePort=49001,DestinationPort=443,
    L4Len=200,Length=240,ProcessId=5001,ProcessName=name
  };
  public static IEnumerable<object[]> HttpCases()
  {
    yield return new object[]{"R616","POST","/ecp/DDI/DDIService.svc/SetObject?schema=Reset&object=VirtualDirectory","/ecp/DDI/DDIService.svc/SetObject?schema=Inspect&object=VirtualDirectory"};
    yield return new object[]{"R617","GET","/SolarWinds/Orion/LogoImageHandler.ashx?clazz=Example","/SolarWinds/Orion/LogoImageHandler.ashx?version=1"};
    yield return new object[]{"R618","GET","/autodiscover/autodiscover.json?target=/powershell","/autodiscover/autodiscover.json?target=/calendar"};
    yield return new object[]{"R619","GET","/api/v1/search?x=%24%7B%40java","/api/v1/search?x=java"};
  }
  public static IEnumerable<object[]> DnsCases()
  {
    yield return new object[]{"R620","tunnel.localto.net","tunnel.localto.net.evil.test"};
    yield return new object[]{"R621","api.akamaicontainer.com","api.akamaicontainer.com.evil.test"};
  }
  public static IEnumerable<object[]> ProcessCases()
  {
    yield return new object[]{"R622","notepad.exe","wordpad.exe"};
    yield return new object[]{"R623","dialer.exe","explorer.exe"};
    yield return new object[]{"R624","addinutil.exe","msiexec.exe"};
    yield return new object[]{"R625","eqnedt32.exe","winword.exe"};
  }

  [Theory,MemberData(nameof(HttpCases))]
  public async Task Http_Independent_Signature_Positive_And_Benign_Negative(string id,string method,string hit,string benign)
  {
    var positive=await New(id).EvaluateAsync(At(Http(method,hit)));
    Assert.True(positive.Matched);Assert.Equal(id,Assert.Single(positive.Events).RuleId);
    Assert.False((await New(id).EvaluateAsync(At(Http(method,benign)))).Matched);
  }
  [Theory,MemberData(nameof(HttpCases))]
  public async Task Http_Wrong_Producer_And_Info_Only_Negative(string id,string method,string hit,string benign)
  {
    var rule=New(id);
    var wrong=Http(method,hit);wrong.ApplicationProtocol="TLS";
    var info=Http(method,"/safe");info.Info=hit;
    var tls=Http(method,hit);tls.TlsVersion="TLS1.3";
    Assert.False((await rule.EvaluateAsync(At(wrong))).Matched);
    Assert.False((await rule.EvaluateAsync(At(info,1))).Matched);
    Assert.False((await rule.EvaluateAsync(At(tls,2))).Matched);
  }
  [Theory,MemberData(nameof(HttpCases))]
  public async Task Http_Url_Redaction_Duplicate_And_Cooldown(string id,string method,string hit,string benign)
  {
    var rule=New(id);var r=Http(method,hit);
    var ev=Assert.Single((await rule.EvaluateAsync(At(r,10))).Events);
    var body=JsonSerializer.Serialize(ev);
    Assert.DoesNotContain(hit,body);Assert.Contains("request_only_unknown",body);
    Assert.False((await rule.EvaluateAsync(At(r,11))).Matched);
    Assert.False((await rule.EvaluateAsync(At(Http(method,hit),9))).Matched);
    var cooldown=await rule.EvaluateAsync(At(Http(method,hit),12));
    Assert.True(cooldown.Suppressed);Assert.Empty(cooldown.Events);
    Assert.True((await rule.EvaluateAsync(At(Http(method,hit),611))).Matched);
  }
  [Theory,MemberData(nameof(DnsCases))]
  public async Task Dns_Parsed_Query_Positive_And_Suffix_Impersonation_Negative(string id,string hit,string benign)
  {
    var positive=await New(id).EvaluateAsync(At(Dns(hit)));
    Assert.True(positive.Matched);Assert.Equal(id,Assert.Single(positive.Events).RuleId);
    Assert.False((await New(id).EvaluateAsync(At(Dns(benign)))).Matched);
  }
  [Theory,MemberData(nameof(DnsCases))]
  public async Task Dns_Response_Wrong_Port_Missing_Service_And_Malformed_Negative(string id,string hit,string benign)
  {
    var rule=New(id);
    var answer=Dns(hit);answer.DnsIsResponse=true;
    var port=Dns(hit);port.DestinationPort=5353;
    var spoof=Dns(hit);spoof.ApplicationService=null;spoof.Info=hit;
    var invalid=Dns(hit);invalid.DnsQname=hit+"\\r\\n";
    Assert.False((await rule.EvaluateAsync(At(answer))).Matched);
    Assert.False((await rule.EvaluateAsync(At(port,1))).Matched);
    Assert.False((await rule.EvaluateAsync(At(spoof,2))).Matched);
    Assert.False((await rule.EvaluateAsync(At(invalid,3))).Matched);
  }
  [Theory,MemberData(nameof(DnsCases))]
  public async Task Dns_Redaction_Cooldown_And_Replay_Guard(string id,string hit,string benign)
  {
    var rule=New(id);var r=Dns(hit);
    var evt=Assert.Single((await rule.EvaluateAsync(At(r,10))).Events);
    var body=JsonSerializer.Serialize(evt);
    Assert.DoesNotContain(hit,body);Assert.Contains("dns_query_only_unknown",body);
    Assert.False((await rule.EvaluateAsync(At(r,11))).Matched);
    Assert.False((await rule.EvaluateAsync(At(Dns(hit),9))).Matched);
    var cooldown=await rule.EvaluateAsync(At(Dns(hit),12));
    Assert.True(cooldown.Suppressed);Assert.Empty(cooldown.Events);
    Assert.True((await rule.EvaluateAsync(At(Dns(hit),611))).Matched);
  }
  [Theory,MemberData(nameof(ProcessCases))]
  public async Task Process_Exact_Local_Resolved_Name_And_Benign_Negative(string id,string process,string benign)
  {
    var matched=await New(id).EvaluateAsync(At(Process(process)));
    Assert.True(matched.Matched);Assert.Equal(id,Assert.Single(matched.Events).RuleId);
    Assert.False((await New(id).EvaluateAsync(At(Process(benign)))).Matched);
  }
  [Theory,MemberData(nameof(ProcessCases))]
  public async Task Process_Missing_Pid_Internal_Target_And_Contradictions_Reject(string id,string process,string benign)
  {
    var rule=New(id);
    var missing=Process(process);missing.ProcessId=0;
    var inside=Process(process);inside.Destination="10.3.1.10";
    var noName=Process(process);noName.ProcessName=null;
    var udp=Process(process);udp.IsTcp=false;udp.IsUdp=true;
    Assert.False((await rule.EvaluateAsync(At(missing))).Matched);
    Assert.False((await rule.EvaluateAsync(At(inside,1))).Matched);
    Assert.False((await rule.EvaluateAsync(At(noName,2))).Matched);
    Assert.False((await rule.EvaluateAsync(At(udp,3))).Matched);
  }
  [Theory,MemberData(nameof(ProcessCases))]
  public async Task Process_Redacted_Path_Cooldown_And_Duplicate(string id,string process,string benign)
  {
    var rule=New(id);var r=Process(process);
    var evt=Assert.Single((await rule.EvaluateAsync(At(r,10))).Events);
    var serialized=JsonSerializer.Serialize(evt);
    Assert.Contains("process_flow_identity_unverified",serialized);
    Assert.DoesNotContain("\\Windows\\System32\\",serialized);
    Assert.False((await rule.EvaluateAsync(At(r,11))).Matched);
    var second=await rule.EvaluateAsync(At(Process(process),12));
    Assert.True(second.Suppressed);Assert.Empty(second.Events);
  }
  [Fact]
  public async Task NotepadPrinterPort9100Exclusion()
  {
    var r=Process("notepad.exe");r.DestinationPort=9100;
    Assert.False((await New("R622").EvaluateAsync(At(r))).Matched);
  }
  [Fact]
  public async Task Exchanging_Backend_And_OWA_Signatures_Does_Not_Converge()
  {
    var a=Http("GET","/autodiscover/autodiscover.json?target=/powershell");
    Assert.True((await New("R618").EvaluateAsync(At(a))).Matched);
    Assert.False((await New("R616").EvaluateAsync(At(a))).Matched);
    var b=Http("POST","/ecp/DDI/DDIService.svc/SetObject?schema=Reset&object=VirtualDirectory");
    Assert.True((await New("R616").EvaluateAsync(At(b))).Matched);
    Assert.False((await New("R618").EvaluateAsync(At(b))).Matched);
  }
  [Fact]
  public void RegistryExactlyTenNewShadowRules()
  {
    var all=RuleRegistry.CreateDefaultRules();
    foreach(var id in Ids)
    {
      var item=Assert.Single(all.Where(r=>r.Descriptor.RuleId==id));
      var precision=Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(item);
      Assert.Equal(RuleRuntimeMode.Shadow,precision.PrecisionProfile.DefaultMode);
      Assert.Equal(RulePrecisionMaturity.Candidate,precision.PrecisionProfile.Maturity);
    }
    Assert.Equal(Ids.Length,all.Count(r=>Ids.Contains(r.Descriptor.RuleId)));
  }
}
