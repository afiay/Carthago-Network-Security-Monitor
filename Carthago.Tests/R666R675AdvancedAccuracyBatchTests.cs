// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit cases authored; zero executed.
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
public sealed class R666R675AdvancedAccuracyBatchTests
{
 private static readonly DateTime Epoch=new(2026,11,3,22,0,0,DateTimeKind.Utc);
 private static IDetectionRule Rule(string id)=>id switch{
 "R666"=>new R666_SpecificSqlInjectionGetUriRequestRule(),
 "R667"=>new R667_ScriptProcessMqttControlTopicPublishRule(),
 "R668"=>new R668_Rundll32CleartextApiPostPublicRule(),
 "R669"=>new R669_SystemBinaryTlsClientOnCleartextPort80Rule(),
 "R670"=>new R670_RegularFixedLengthIcmpEchoSequenceRule(),
 "R671"=>new R671_ScriptProcessLargeRawTcpPayloadBurstRule(),
 "R672"=>new R672_PowerShellBase64LikeHttpPostParameterRule(),
 "R673"=>new R673_ScriptProcessRepeatedDoublePercentEncodedHttpGetRule(),
 "R674"=>new R674_SameProcessInboundToOutboundPublicTcpSynSequenceRule(),
 "R675"=>new R675_UnusualSystemUtilityTlsSniToWebCollaborationHostRule(),
 _=>throw new ArgumentOutOfRangeException(nameof(id))};
 private static RuleEvaluationContext At(TrafficRecord r,int seconds=0)
   =>new(r,Sensitivity.Balanced,Epoch.AddSeconds(seconds));
 private static TrafficRecord Http(string method,string uri,string process="powershell.exe")
   =>new(){
     Id=Guid.NewGuid(),Source="10.1.2.20",Destination="8.8.8.8",IpVersion=4,
     Protocol="TCP",IsTcp=true,SourcePort=51020,DestinationPort=8080,
     L4Len=300,Length=340,ApplicationProtocol="HTTP",HttpMethod=method,
     HttpUri=uri,HttpHost="api.example.test",ProcessId=3100,ProcessName=process
   };
 private static TrafficRecord Tcp(string process,int port=4444,int length=1800)
   =>new(){
     Id=Guid.NewGuid(),Source="10.1.2.20",Destination="8.8.8.8",IpVersion=4,
     Protocol="TCP",IsTcp=true,SourcePort=51021,DestinationPort=port,
     L4Len=length,Length=length+40,ProcessName=process,ProcessId=3100
   };
 private static TrafficRecord Echo(int length=64)
   =>new(){
     Id=Guid.NewGuid(),Source="10.1.2.20",Destination="8.8.8.8",IpVersion=4,
     Protocol="ICMP",IsTcp=false,IsUdp=false,Length=length+40,L4Len=length,
     IcmpTypeCode=0x0800
   };
 [Fact] public async Task SqlGetRequiresConcreteQuerySelectorNotInfoOnly()
 {
   var rule=Rule("R666");
   Assert.True((await rule.EvaluateAsync(At(Http("GET","/search?q=UNION%20SELECT+username")))).Matched);
   Assert.False((await Rule("R666").EvaluateAsync(At(Http("GET","/search?q=union")))).Matched);
   Assert.False((await Rule("R666").EvaluateAsync(At(Http("POST","/search?q=UNION%20SELECT")))).Matched);
   var info=Http("GET","/safe");info.Info="/search?q=UNION%20SELECT";
   Assert.False((await Rule("R666").EvaluateAsync(At(info))).Matched);
 }
 [Fact] public async Task MqttControlPublishRequiresParserFlagsProcessAndNoRetain()
 {
   var r=Tcp("powershell.exe",1883,90);r.ApplicationProtocol="mqtt.publish";
   r.MqttPublishTopicObserved=true;r.MqttControlTopicObserved=true;r.MqttRetain=false;
   Assert.True((await Rule("R667").EvaluateAsync(At(r))).Matched);
   var wrong=Tcp("chrome.exe",1883,90);wrong.ApplicationProtocol="mqtt.publish";
   wrong.MqttPublishTopicObserved=true;wrong.MqttControlTopicObserved=true;wrong.MqttRetain=false;
   Assert.False((await Rule("R667").EvaluateAsync(At(wrong))).Matched);
   var retained=Tcp("powershell.exe",1883,90);retained.ApplicationProtocol="mqtt.publish";
   retained.MqttPublishTopicObserved=true;retained.MqttControlTopicObserved=true;retained.MqttRetain=true;
   Assert.False((await Rule("R667").EvaluateAsync(At(retained))).Matched);
 }
 [Fact] public async Task Rundll32HttpRequiresApiPostAndPort()
 {
   Assert.True((await Rule("R668").EvaluateAsync(At(Http("POST","/api/checkin","rundll32.exe")))).Matched);
   Assert.False((await Rule("R668").EvaluateAsync(At(Http("POST","/home","rundll32.exe")))).Matched);
   Assert.False((await Rule("R668").EvaluateAsync(At(Http("GET","/api/checkin","rundll32.exe")))).Matched);
   Assert.False((await Rule("R668").EvaluateAsync(At(Http("POST","/api/checkin","chrome.exe")))).Matched);
 }
 [Fact] public async Task TlsPort80RequiresSniSystemUtilityAndNoHttp()
 {
   var r=Tcp("mshta.exe",80,120);r.TlsVersion="TLS1.3";r.Sni="api.example.test";
   Assert.True((await Rule("R669").EvaluateAsync(At(r))).Matched);
   var other=Tcp("mshta.exe",443,120);other.TlsVersion="TLS1.3";other.Sni="api.example.test";
   Assert.False((await Rule("R669").EvaluateAsync(At(other))).Matched);
   var noSni=Tcp("mshta.exe",80,120);noSni.TlsVersion="TLS1.3";
   Assert.False((await Rule("R669").EvaluateAsync(At(noSni))).Matched);
 }
 [Fact] public async Task TimedIcmpRequiresFourSameSizeAndRegularSpacing()
 {
   var rule=Rule("R670");
   Assert.False((await rule.EvaluateAsync(At(Echo(),0))).Matched);
   Assert.False((await rule.EvaluateAsync(At(Echo(),12))).Matched);
   Assert.False((await rule.EvaluateAsync(At(Echo(),24))).Matched);
   Assert.True((await rule.EvaluateAsync(At(Echo(),36))).Matched);
   var irregular=Rule("R670");
   Assert.False((await irregular.EvaluateAsync(At(Echo(),0))).Matched);
   Assert.False((await irregular.EvaluateAsync(At(Echo(),1))).Matched);
   Assert.False((await irregular.EvaluateAsync(At(Echo(200),13))).Matched);
   var tcp=Echo();tcp.Protocol="TCP";tcp.IsTcp=true;
   Assert.False((await Rule("R670").EvaluateAsync(At(tcp))).Matched);
 }
 [Fact] public async Task RawTcpBurstRequiresEightHeavyPacketsFromSameScriptPeer()
 {
   var rule=Rule("R671");
   for(int i=0;i<7;i++)
     Assert.False((await rule.EvaluateAsync(At(Tcp("python.exe",4444,1800),i+1))).Matched);
   Assert.True((await rule.EvaluateAsync(At(Tcp("python.exe",4444,1800),8))).Matched);
   var browser=Tcp("chrome.exe");Assert.False((await Rule("R671").EvaluateAsync(At(browser))).Matched);
   var http=Tcp("python.exe");http.HttpMethod="POST";
   Assert.False((await Rule("R671").EvaluateAsync(At(http))).Matched);
 }
 [Fact] public async Task Base64LikePostRequiresPowerShellAndNamedHost()
 {
   var data=new string('A',80)+new string('7',11)+"_";
   var yes=Http("POST","/api/submit?data="+data);
   Assert.True((await Rule("R672").EvaluateAsync(At(yes))).Matched);
   var browser=Http("POST","/api/submit?data="+data,"chrome.exe");
   Assert.False((await Rule("R672").EvaluateAsync(At(browser))).Matched);
   var host=Http("POST","/api/submit?data="+data);host.HttpHost="8.8.8.8";
   Assert.False((await Rule("R672").EvaluateAsync(At(host))).Matched);
   var shortUri=Http("POST","/api/submit?data=AAAA7_");
   Assert.False((await Rule("R672").EvaluateAsync(At(shortUri))).Matched);
 }
 [Fact] public async Task DoubleEncodedGetRequiresFourDistinctMarkersAndScript()
 {
   var uri="/browse?q=%252f%253a%252f%253b";
   Assert.True((await Rule("R673").EvaluateAsync(At(Http("GET",uri,"python.exe")))).Matched);
   Assert.False((await Rule("R673").EvaluateAsync(At(Http("GET","/browse?q=%252f","python.exe")))).Matched);
   Assert.False((await Rule("R673").EvaluateAsync(At(Http("GET",uri,"chrome.exe")))).Matched);
 }
 [Fact] public async Task ProxyBridgeRequiresOrderedSynsWithSamePidAndLocalHost()
 {
   var rule=Rule("R674");
   var inbound=Tcp("powershell.exe",9000,0);
   inbound.Source="9.9.9.9";inbound.Destination="10.1.2.20";
   inbound.SourcePort=53111;inbound.TcpFlags=0x02;
   var outbound=Tcp("powershell.exe",9090,0);outbound.TcpFlags=0x02;
   Assert.False((await rule.EvaluateAsync(At(inbound,0))).Matched);
   Assert.True((await rule.EvaluateAsync(At(outbound,1))).Matched);
   var isolated=Rule("R674");
   Assert.False((await isolated.EvaluateAsync(At(outbound,0))).Matched);
   var wrongPid=Tcp("powershell.exe",9090,0);wrongPid.TcpFlags=0x02;wrongPid.ProcessId=9000;
   Assert.False((await isolated.EvaluateAsync(At(inbound,1))).Matched);
   Assert.False((await isolated.EvaluateAsync(At(wrongPid,2))).Matched);
 }
 [Fact] public async Task CollaborationSniRequiresAtypicalSystemUtilityAndSpecificHostname()
 {
   var r=Tcp("rundll32.exe",443,90);r.TlsVersion="TLS1.3";r.Sni="files.slack.com";
   Assert.True((await Rule("R675").EvaluateAsync(At(r))).Matched);
   var fake=Tcp("rundll32.exe",443,90);fake.TlsVersion="TLS1.3";fake.Sni="files.slack.com.evil.test";
   Assert.False((await Rule("R675").EvaluateAsync(At(fake))).Matched);
   var normal=Tcp("chrome.exe",443,90);normal.TlsVersion="TLS1.3";normal.Sni="files.slack.com";
   Assert.False((await Rule("R675").EvaluateAsync(At(normal))).Matched);
 }
 [Theory]
 [InlineData("R666")]
 [InlineData("R667")]
 [InlineData("R668")]
 [InlineData("R669")]
 [InlineData("R670")]
 [InlineData("R671")]
 [InlineData("R672")]
 [InlineData("R673")]
 [InlineData("R674")]
 [InlineData("R675")]
 public void UniqueRegisteredCandidateShadow(string id)
 {
    var found=Assert.Single(RuleRegistry.CreateDefaultRules().Where(r=>r.Descriptor.RuleId==id));
    var profile=Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(found);
    Assert.Equal(RuleRuntimeMode.Shadow,profile.PrecisionProfile.DefaultMode);
    Assert.Equal(RulePrecisionMaturity.Candidate,profile.PrecisionProfile.Maturity);
 }
 [Fact] public async Task EventScopeAndDuplicateCooldownDoNotClaimExploitation()
 {
   var rule=Rule("R666");var r=Http("GET","/search?q=UNION%20SELECT+username");
   var evt=Assert.Single((await rule.EvaluateAsync(At(r,10))).Events);
   var json=JsonSerializer.Serialize(evt);
   Assert.Contains("http_sqli_request_only_unknown",json);
   Assert.DoesNotContain("successful exploitation",json,StringComparison.OrdinalIgnoreCase);
   Assert.False((await rule.EvaluateAsync(At(r,11))).Matched);
   var repeat=Http("GET","/search?q=UNION%20SELECT+username");
   Assert.True((await rule.EvaluateAsync(At(repeat,12))).Suppressed);
   Assert.True((await rule.EvaluateAsync(At(Http("GET","/search?q=UNION%20SELECT+username"),611))).Matched);
 }
}
