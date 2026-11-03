// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Authored xUnit: 0 tests executed.
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
public sealed class R636R645AdvancedAccuracyBatchTests
{
 private static readonly DateTime Origin=new(2026,11,3,21,0,0,DateTimeKind.Utc);
 private static IDetectionRule Rule(string id)=>id switch{
 "R636"=>new R636_OmigodUnauthenticatedWsmanPostRequestRule(),
 "R637"=>new R637_HistoricalGalliumDnsIndicatorQueryRule(),
 "R638"=>new R638_MultiPortSuspiciousCallbackProcessEgressRule(),
 "R639"=>new R639_NgrokDevProcessTlsSniEgressRule(),
 "R640"=>new R640_NgrokRegionalTunnelProcessTlsSniRule(),
 "R641"=>new R641_OfficeProcessHighEntropyDnsQueryRule(),
 "R642"=>new R642_ScriptProcessBrowserAgentHttpPostRule(),
 "R643"=>new R643_SequentialEtherNetIpListIdentitySubnetWalkRule(),
 "R644"=>new R644_RdpPublicClientSynAckExposureEvidenceRule(),
 "R645"=>new R645_PunycodeLoginFormPostExposureRule(),
 _=>throw new ArgumentOutOfRangeException(nameof(id))};
 private static RuleEvaluationContext At(TrafficRecord r,int sec=0)=>new(r,Sensitivity.Balanced,Origin.AddSeconds(sec));
 private static TrafficRecord Http(string method,string uri,string headers="Host: service.lab",string ua="curl/8.0")=>new()
 {
  Id=Guid.NewGuid(),Source="10.1.1.20",Destination="10.1.1.40",IpVersion=4,
  IsTcp=true,Protocol="TCP",SourcePort=50000,DestinationPort=80,L4Len=160,Length=200,
  ApplicationProtocol="HTTP",HttpMethod=method,HttpUri=uri,HttpHost="service.lab",
  HttpRequestHeaders=headers,HttpUserAgent=ua
 };
 private static TrafficRecord Dns(string query)=>new()
 {
  Id=Guid.NewGuid(),Source="10.1.1.20",Destination="10.1.1.53",IpVersion=4,
  IsUdp=true,Protocol="UDP",SourcePort=51516,DestinationPort=53,L4Len=100,Length=142,
  ApplicationService="DNS",DnsQname=query,DnsQtype="A"
 };
 private static TrafficRecord Process(string name,int port=443)=>new()
 {
  Id=Guid.NewGuid(),Source="10.1.1.20",Destination="8.8.8.8",IpVersion=4,
  IsTcp=true,Protocol="TCP",SourcePort=51515,DestinationPort=port,L4Len=180,Length=220,
  ProcessId=3456,ProcessName=name
 };
 private static TrafficRecord Ot(int destLast)=>new()
 {
  Id=Guid.NewGuid(),Source="10.3.1.10",Destination="10.3.2."+destLast,IpVersion=4,
  IsTcp=true,Protocol="TCP",SourcePort=51000,DestinationPort=44818,
  L4Len=40,Length=90,ApplicationProtocol="ethernetip.listidentity"
 };

 [Fact] public async Task R636_Valid_Request_Positive_And_AuthOrEmptyBody_Negative()
 {
  var headers="Host: service.lab\nContent-Length: 27";
  Assert.True((await Rule("R636").EvaluateAsync(At(Http("POST","/wsman",headers)))).Matched);
  Assert.False((await Rule("R636").EvaluateAsync(At(Http("POST","/wsman",headers+"\nAuthorization: [REDACTED]")))).Matched);
  Assert.False((await Rule("R636").EvaluateAsync(At(Http("POST","/wsman","Host: service.lab\nContent-Length: 0")))).Matched);
  Assert.False((await Rule("R636").EvaluateAsync(At(Http("GET","/wsman",headers)))).Matched);
 }
 [Fact] public async Task R637_Historical_Domain_Query_And_Impersonation()
 {
  Assert.True((await Rule("R637").EvaluateAsync(At(Dns("asyspy256.ddns.net")))).Matched);
  Assert.False((await Rule("R637").EvaluateAsync(At(Dns("asyspy256.ddns.net.evil.test")))).Matched);
  var response=Dns("asyspy256.ddns.net");response.DnsIsResponse=true;
  Assert.False((await Rule("R637").EvaluateAsync(At(response))).Matched);
 }
 [Fact] public async Task R638_Requires_Two_Distinct_Callback_Ports_And_Process_Identity()
 {
  var rule=Rule("R638");Assert.False((await rule.EvaluateAsync(At(Process("powershell.exe",4444)))).Matched);
  Assert.False((await rule.EvaluateAsync(At(Process("powershell.exe",4444),1))).Matched);
  var e=await rule.EvaluateAsync(At(Process("powershell.exe",8531),2));
  Assert.True(e.Matched);Assert.Equal("R638",Assert.Single(e.Events).RuleId);
  var wrong=Process("powershell.exe",4444);wrong.ProcessId=0;
  Assert.False((await Rule("R638").EvaluateAsync(At(wrong))).Matched);
 }
 [Fact] public async Task R638_Mixed_Public_Peers_And_Stale_Times_Never_Combine()
 {
  var rule=Rule("R638");Assert.False((await rule.EvaluateAsync(At(Process("powershell.exe",4444)))).Matched);
  var other=Process("powershell.exe",8531);other.Destination="9.9.9.9";
  Assert.False((await rule.EvaluateAsync(At(other,1))).Matched);
  Assert.False((await rule.EvaluateAsync(At(Process("powershell.exe",8531),301))).Matched);
 }
 [Fact] public async Task R639_And_R640_Use_Different_Ngrok_Name_Families()
 {
  var dev=Process("powershell.exe");dev.TlsVersion="TLS1.3";dev.Sni="sub.ngrok-free.dev";
  Assert.True((await Rule("R639").EvaluateAsync(At(dev))).Matched);
  Assert.False((await Rule("R640").EvaluateAsync(At(dev))).Matched);
  var region=Process("powershell.exe");region.TlsVersion="TLS1.3";region.Sni="tunnel.eu.ngrok.com";
  Assert.True((await Rule("R640").EvaluateAsync(At(region))).Matched);
  Assert.False((await Rule("R639").EvaluateAsync(At(region))).Matched);
  var fake=Process("powershell.exe");fake.TlsVersion="TLS1.3";fake.Sni="tunnel.eu.ngrok.com.evil.test";
  Assert.False((await Rule("R640").EvaluateAsync(At(fake))).Matched);
 }
 [Fact] public async Task R641_Office_High_Entropy_Query_Requires_Process_And_Valid_Dns()
 {
  var value="a1b2c3d4e5f6g7h8i9j0k1l2.example";
  var r=Dns(value);r.ProcessId=1234;r.ProcessName="winword.exe";
  Assert.True((await Rule("R641").EvaluateAsync(At(r))).Matched);
  var noPid=Dns(value);noPid.ProcessName="winword.exe";
  Assert.False((await Rule("R641").EvaluateAsync(At(noPid))).Matched);
  var regular=Dns("office.microsoft.com");regular.ProcessId=1234;regular.ProcessName="winword.exe";
  Assert.False((await Rule("R641").EvaluateAsync(At(regular))).Matched);
 }
 [Fact] public async Task R642_Script_Process_Mimicking_Browser_On_Post()
 {
  var r=Http("POST","/api/upload",ua:"Mozilla/5.0 Chrome/105.0.5195.54");
  r.ProcessId=345;r.ProcessName="powershell.exe";
  Assert.True((await Rule("R642").EvaluateAsync(At(r))).Matched);
  var browser=Http("POST","/api/upload",ua:"Mozilla/5.0 Chrome/105.0.5195.54");
  browser.ProcessId=345;browser.ProcessName="chrome.exe";
  Assert.False((await Rule("R642").EvaluateAsync(At(browser))).Matched);
  var noPid=Http("POST","/api/upload",ua:"Mozilla/5.0 Chrome/105.0.5195.54");
  noPid.ProcessName="powershell.exe";
  Assert.False((await Rule("R642").EvaluateAsync(At(noPid))).Matched);
 }
 [Fact] public async Task R643_ListIdentity_Requires_Sequential_Hosts_Not_Repeat_Or_OutOfOrder()
 {
  var rule=Rule("R643");
  Assert.False((await rule.EvaluateAsync(At(Ot(10)))).Matched);
  Assert.False((await rule.EvaluateAsync(At(Ot(11),1))).Matched);
  Assert.True((await rule.EvaluateAsync(At(Ot(12),2))).Matched);
  var other=Rule("R643");
  Assert.False((await other.EvaluateAsync(At(Ot(10)))).Matched);
  Assert.False((await other.EvaluateAsync(At(Ot(12),1))).Matched);
  Assert.False((await other.EvaluateAsync(At(Ot(11),2))).Matched);
 }
 [Fact] public async Task R644_Only_Rdp_Server_SynAck_To_Public_IP()
 {
  var r=Process("svchost.exe",443);r.SourcePort=3389;r.TcpFlags=0x12;r.L4Len=0;
  Assert.True((await Rule("R644").EvaluateAsync(At(r))).Matched);
  var syn=Process("svchost.exe",443);syn.SourcePort=3389;syn.TcpFlags=0x02;
  Assert.False((await Rule("R644").EvaluateAsync(At(syn))).Matched);
  var nonPublic=Process("svchost.exe",443);nonPublic.SourcePort=3389;nonPublic.TcpFlags=0x12;nonPublic.Destination="10.4.1.5";
  Assert.False((await Rule("R644").EvaluateAsync(At(nonPublic))).Matched);
 }
 [Fact] public async Task R645_Punycode_Host_Login_Form_Post_And_Benign_Host()
 {
  var r=Http("POST","/login","Host: xn--secure-9ja.example\nContent-Type: application/x-www-form-urlencoded");
  r.HttpHost="xn--secure-9ja.example";
  Assert.True((await Rule("R645").EvaluateAsync(At(r))).Matched);
  var ordinary=Http("POST","/login","Content-Type: application/x-www-form-urlencoded");ordinary.HttpHost="secure.example";
  Assert.False((await Rule("R645").EvaluateAsync(At(ordinary))).Matched);
  var get=Http("GET","/login","Content-Type: application/x-www-form-urlencoded");get.HttpHost="xn--secure-9ja.example";
  Assert.False((await Rule("R645").EvaluateAsync(At(get))).Matched);
 }
 [Theory][InlineData("R636")][InlineData("R637")][InlineData("R638")]
 [InlineData("R639")][InlineData("R640")][InlineData("R641")][InlineData("R642")]
 [InlineData("R643")][InlineData("R644")][InlineData("R645")]
 public void Rule_Registered_Exactly_Once_Candidate_Shadow(string id)
 {
  var matches=RuleRegistry.CreateDefaultRules().Where(r=>r.Descriptor.RuleId==id).ToArray();
  var p=Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(Assert.Single(matches));
  Assert.Equal(RuleRuntimeMode.Shadow,p.PrecisionProfile.DefaultMode);
  Assert.Equal(RulePrecisionMaturity.Candidate,p.PrecisionProfile.Maturity);
 }
 [Fact] public async Task Distinct_Ids_OutOfOrder_And_Cooldown_No_Replay()
 {
  var rule=Rule("R639");var packet=Process("powershell.exe");packet.TlsVersion="TLS1.3";packet.Sni="x.ngrok-free.dev";
  var first=await rule.EvaluateAsync(At(packet,10));Assert.Single(first.Events);
  Assert.False((await rule.EvaluateAsync(At(packet,11))).Matched);
  var early=Process("powershell.exe");early.TlsVersion="TLS1.3";early.Sni="x.ngrok-free.dev";
  Assert.False((await rule.EvaluateAsync(At(early,9))).Matched);
  var later=Process("powershell.exe");later.TlsVersion="TLS1.3";later.Sni="x.ngrok-free.dev";
  var suppressed=await rule.EvaluateAsync(At(later,12));Assert.True(suppressed.Suppressed);
  var after=Process("powershell.exe");after.TlsVersion="TLS1.3";after.Sni="x.ngrok-free.dev";
  Assert.True((await rule.EvaluateAsync(At(after,611))).Matched);
 }
 [Fact] public async Task Historical_Dns_Qname_Redacted_In_Event()
 {
  var qname="asyspy256.ddns.net";
  var result=await Rule("R637").EvaluateAsync(At(Dns(qname)));
  var serialized=JsonSerializer.Serialize(Assert.Single(result.Events));
  Assert.DoesNotContain(qname,serialized,StringComparison.OrdinalIgnoreCase);
  Assert.Contains("dns_query_only_unknown",serialized);
 }
}
