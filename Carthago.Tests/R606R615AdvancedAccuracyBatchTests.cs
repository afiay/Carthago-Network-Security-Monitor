// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed.
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
public sealed class R606R615AdvancedAccuracyBatchTests
{
 static readonly DateTime Origin=new(2026,11,3,18,0,0,DateTimeKind.Utc);
 static readonly string[] Ids={"R606","R607","R608","R609","R610","R611","R612","R613","R614","R615"};
 static IDetectionRule Rule(string id)=>id switch
 {
   "R606"=>new R606_PulseGuacamoleQueryRequestRule(),
   "R607"=>new R607_KempLoadMasterApiEnableGetRule(),
   "R608"=>new R608_ExchangeMastermailboxPowerShellRequestRule(),
   "R609"=>new R609_ExchangeEncodedAtPowerShellRequestRule(),
   "R610"=>new R610_ExchangeOwaCalendarEndpointPostRule(),
   "R611"=>new R611_FortinetSamlRemoteserverPostRule(),
   "R612"=>new R612_ExternalOastCallbackDnsQueryRule(),
   "R613"=>new R613_CobaltStrikeLikeDnsStagingLabelRule(),
   "R614"=>new R614_HistoricalDprkDomainDnsQueryRule(),
   "R615"=>new R615_AnonfilesDomainDnsQueryRule(),
   _=>throw new ArgumentOutOfRangeException(nameof(id))
 };
 static RuleEvaluationContext At(TrafficRecord r,int sec=0)
  =>new(r,Sensitivity.Balanced,Origin.AddSeconds(sec));
 static TrafficRecord Http(string method,string uri,string agent,string headers)=>new()
 {
   Id=Guid.NewGuid(),Source="10.9.1.20",Destination="10.9.1.30",IpVersion=4,
   Protocol="TCP",IsTcp=true,SourcePort=49001,DestinationPort=8080,
   L4Len=400,Length=512,ApplicationProtocol="HTTP",HttpMethod=method,
   HttpUri=uri,HttpUserAgent=agent,HttpRequestHeaders=headers,HttpHost="server.lab"
 };
 static TrafficRecord Dns(string qname)=>new()
 {
   Id=Guid.NewGuid(),Source="10.9.1.20",Destination="10.9.1.53",IpVersion=4,
   Protocol="UDP",IsUdp=true,SourcePort=53111,DestinationPort=53,
   L4Len=70,Length=112,ApplicationService="DNS",DnsQname=qname,DnsQtype="A"
 };
 public static IEnumerable<object[]> HttpCases()
 {
  yield return new object[]{"R606","GET","/vpn/login?redir=/dana/html5acc/guacamole/../../etc/passwd","/dana/html5acc/guacamole/index.html","curl/8.0","Host: vpn.lab"};
  yield return new object[]{"R607","GET","/access/set?param=enableapi&value=1","/access/set?param=enableapi&value=0","curl/8.0","Host: kemp.lab"};
  yield return new object[]{"R608","POST","/owa/mastermailbox?destination=/powershell","/owa/mastermailbox?destination=/ecp","Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/105.0.5195.54","Host: mail.lab"};
  yield return new object[]{"R609","POST","/owa/user%40example.test/powershell","/owa/user%40example.test/ecp","curl/8.0","Host: mail.lab"};
  yield return new object[]{"R610","POST","/owa/calendar/a?view=1","/owa/calendar/default?view=1","curl/8.0","Host: mail.lab"};
  yield return new object[]{"R611","POST","/api/v2.0/user/remoteserver.saml","/api/v2.0/user/remoteserver.saml","curl/8.0","Host: fortinet.lab\nReferer: https://other.test/portal"};
 }
 public static IEnumerable<object[]> DnsCases()
 {
  yield return new object[]{"R612","probe.interact.sh","polling.oastify.com"};
  yield return new object[]{"R613","aaa.stage.example.test","normal.stage.example.test"};
  yield return new object[]{"R614","connection.lockscreen.kro.kr","connection.lockscreen.kro.kr.evil.test"};
  yield return new object[]{"R615","upload.anonfiles.com","upload.anonfiles.com.evil.test"};
 }
 [Theory,MemberData(nameof(HttpCases))]
 public async Task Http_Exact_Request_Matches(string id,string method,string uri,string benign,string agent,string headers)
 {
  Assert.False(string.IsNullOrWhiteSpace(benign));
  var result=await Rule(id).EvaluateAsync(At(Http(method,uri,agent,headers)));
  Assert.True(result.Matched);Assert.Equal(id,Assert.Single(result.Events).RuleId);
 }
 [Theory,MemberData(nameof(HttpCases))]
 public async Task Http_Benign_Near_Miss_And_Wrong_Method_Are_Rejected(string id,string method,string uri,string benign,string agent,string headers)
 {
  var rule=Rule(id);var negative=Http(method,benign,agent,headers);
  if(id=="R611")negative.HttpRequestHeaders="Host: fortinet.lab\nReferer: https://fortinet.lab/root/user/remote-user/saml-user/";
  Assert.False((await rule.EvaluateAsync(At(negative))).Matched);
  Assert.False((await rule.EvaluateAsync(At(Http(method=="GET"?"POST":"GET",uri,agent,headers),1))).Matched);
 }
 [Theory,MemberData(nameof(HttpCases))]
 public async Task Http_Contradictory_Fields_And_Spoofed_Info_Fail_Closed(string id,string method,string uri,string benign,string agent,string headers)
 {
  Assert.False(string.IsNullOrWhiteSpace(benign));
  var rule=Rule(id);
  var missing=Http(method,uri,agent,headers);missing.ApplicationProtocol=null;
  var fake=Http(method,"/normal",agent,headers);fake.Info=uri;
  var tls=Http(method,uri,agent,headers);tls.TlsVersion="TLS1.3";
  var dns=Http(method,uri,agent,headers);dns.DnsQname="forged.example";
  Assert.False((await rule.EvaluateAsync(At(missing))).Matched);
  Assert.False((await rule.EvaluateAsync(At(fake,1))).Matched);
  Assert.False((await rule.EvaluateAsync(At(tls,2))).Matched);
  Assert.False((await rule.EvaluateAsync(At(dns,3))).Matched);
 }
 [Theory,MemberData(nameof(HttpCases))]
 public async Task Http_Cooldown_Duplicate_And_Redaction(string id,string method,string uri,string benign,string agent,string headers)
 {
  Assert.False(string.IsNullOrWhiteSpace(benign));
  var rule=Rule(id);var r=Http(method,uri,agent,headers);
  var result=await rule.EvaluateAsync(At(r,10));var e=Assert.Single(result.Events);
  var encoded=JsonSerializer.Serialize(e);
  Assert.DoesNotContain(uri,encoded);Assert.Contains("request_only_unknown",encoded);
  Assert.False((await rule.EvaluateAsync(At(r,11))).Matched);
  Assert.False((await rule.EvaluateAsync(At(Http(method,uri,agent,headers),9))).Matched);
  var suppressed=await rule.EvaluateAsync(At(Http(method,uri,agent,headers),12));
  Assert.True(suppressed.Suppressed);Assert.Empty(suppressed.Events);
  Assert.True((await rule.EvaluateAsync(At(Http(method,uri,agent,headers),611))).Matched);
 }
 [Theory,MemberData(nameof(DnsCases))]
 public async Task Dns_Exact_Query_Matches(string id,string qname,string benign)
 {
  var rule=Rule(id);
  Assert.False((await rule.EvaluateAsync(At(Dns(benign),-1))).Matched);
  var result=await rule.EvaluateAsync(At(Dns(qname)));
  Assert.True(result.Matched);Assert.Equal(id,Assert.Single(result.Events).RuleId);
 }
 [Theory,MemberData(nameof(DnsCases))]
 public async Task Dns_Benign_Query_And_Impersonation_Reject(string id,string qname,string benign)
 {
  Assert.False(string.IsNullOrWhiteSpace(qname));
  Assert.False((await Rule(id).EvaluateAsync(At(Dns(benign)))).Matched);
 }
 [Theory,MemberData(nameof(DnsCases))]
 public async Task Dns_Wrong_Direction_Port_And_Contradictions_Reject(string id,string qname,string benign)
 {
  var rule=Rule(id);
  Assert.False((await rule.EvaluateAsync(At(Dns(benign),-1))).Matched);
  var response=Dns(qname);response.DnsIsResponse=true;
  var port=Dns(qname);port.DestinationPort=5353;
  var fake=Dns(qname);fake.ApplicationService=null;fake.Info=qname;
  var malformed=Dns(qname);malformed.DnsQname=qname+"\r\nForged: x";
  var tls=Dns(qname);tls.TlsVersion="TLS1.3";
  Assert.False((await rule.EvaluateAsync(At(response))).Matched);
  Assert.False((await rule.EvaluateAsync(At(port,1))).Matched);
  Assert.False((await rule.EvaluateAsync(At(fake,2))).Matched);
  Assert.False((await rule.EvaluateAsync(At(malformed,3))).Matched);
  Assert.False((await rule.EvaluateAsync(At(tls,4))).Matched);
 }
 [Theory,MemberData(nameof(DnsCases))]
 public async Task Dns_Cooldown_Duplicate_And_Redaction(string id,string qname,string benign)
 {
  var rule=Rule(id);
  Assert.False((await rule.EvaluateAsync(At(Dns(benign),8))).Matched);
  var r=Dns(qname);
  var result=await rule.EvaluateAsync(At(r,10));var e=Assert.Single(result.Events);
  var encoded=JsonSerializer.Serialize(e);
  Assert.DoesNotContain(qname,encoded);Assert.Contains("dns_query_only_unknown",encoded);
  Assert.False((await rule.EvaluateAsync(At(r,11))).Matched);
  Assert.False((await rule.EvaluateAsync(At(Dns(qname),9))).Matched);
  var suppressed=await rule.EvaluateAsync(At(Dns(qname),12));
  Assert.True(suppressed.Suppressed);Assert.Empty(suppressed.Events);
  Assert.True((await rule.EvaluateAsync(At(Dns(qname),611))).Matched);
 }
 [Fact]
 public async Task Exchange_Owa_Variants_Remain_Independent()
 {
  var a=Http("POST","/owa/mastermailbox?destination=/powershell","Mozilla/5.0 Chrome/105.0.5195.54","Host: mail.lab");
  Assert.True((await Rule("R608").EvaluateAsync(At(a))).Matched);
  Assert.False((await Rule("R609").EvaluateAsync(At(a))).Matched);
  var b=Http("POST","/owa/user%40test.lab/powershell","curl/8.0","Host: mail.lab");
  Assert.True((await Rule("R609").EvaluateAsync(At(b))).Matched);
  Assert.False((await Rule("R608").EvaluateAsync(At(b))).Matched);
 }
 [Fact]
 public void Registry_Contains_All_Ten_Candidate_Shadow_Rules()
 {
  var all=RuleRegistry.CreateDefaultRules();
  foreach(var id in Ids)
  {
   var found=Assert.Single(all.Where(r=>r.Descriptor.RuleId==id));
   var p=Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(found);
   Assert.Equal(RulePrecisionMaturity.Candidate,p.PrecisionProfile.Maturity);
   Assert.Equal(RuleRuntimeMode.Shadow,p.PrecisionProfile.DefaultMode);
  }
  Assert.Equal(Ids.Length,all.Count(r=>Ids.Contains(r.Descriptor.RuleId)));
 }
}
