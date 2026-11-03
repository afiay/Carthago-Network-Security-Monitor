// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit scenarios authored, none executed.
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
public sealed class R676R685AdvancedAccuracyBatchTests
{
 private static readonly DateTime Epoch=new(2026,11,3,22,0,0,DateTimeKind.Utc);
 private static IDetectionRule Rule(string id)=>id switch{
 "R676"=>new R676_UnicastBroadcastNetworkAddressSynKnockRule(),
 "R677"=>new R677_TlsClientHelloOnDnsOrAltHttpPortRule(),
 "R678"=>new R678_SequentialInternalSubnetIcmpEchoWalkRule(),
 "R679"=>new R679_IndustrialServicePortPublicClientSynAckRule(),
 "R680"=>new R680_UnusualProcessInternalPrivateHostFanoutRule(),
 "R681"=>new R681_UnusualProcessDualPublicProxyPortSynRule(),
 "R682"=>new R682_SystemUtilityBrowserAgentHttpGetHeartbeatRule(),
 "R683"=>new R683_HttpPostDetectedOnModbusServicePortRule(),
 "R684"=>new R684_OpcUaPublicClientSynSynAckExchangeRule(),
 "R685"=>new R685_MultiDeviceLargeS7CommResponseFanInRule(),
 _=>throw new ArgumentOutOfRangeException(nameof(id))};
 private static RuleEvaluationContext At(TrafficRecord r,int seconds=0)=>new(r,Sensitivity.Balanced,Epoch.AddSeconds(seconds));
 private static TrafficRecord Tcp(string source="10.1.2.20",string destination="10.1.2.10",int sport=51000,int dport=443,ushort flags=0x02)
  =>new(){Id=Guid.NewGuid(),Source=source,Destination=destination,IpVersion=4,Protocol="TCP",IsTcp=true,
    SourcePort=sport,DestinationPort=dport,TcpFlags=flags,L4Len=0,Length=40};
 private static TrafficRecord ProcessSyn(string destination,string name="rundll32.exe",int port=8080)
 {
    var r=Tcp("10.1.2.20",destination,51000,port);r.ProcessId=1234;r.ProcessName=name;return r;
 }
 private static TrafficRecord Icmp(string destination)
   =>new(){Id=Guid.NewGuid(),Source="10.1.2.20",Destination=destination,IpVersion=4,
      Protocol="ICMP",IcmpTypeCode=0x0800,L4Len=64,Length=100};
 private static TrafficRecord Http(string method,string uri,string source="10.1.2.20",string destination="8.8.8.8",int dport=80)
   =>new(){Id=Guid.NewGuid(),Source=source,Destination=destination,IpVersion=4,
      Protocol="TCP",IsTcp=true,SourcePort=53000,DestinationPort=dport,
      L4Len=240,Length=280,ApplicationProtocol="HTTP",HttpMethod=method,HttpUri=uri,
      HttpUserAgent="Mozilla/5.0 Chrome/118.0",HttpHost="web.example.test",
      ProcessId=1234,ProcessName="rundll32.exe"};
 [Fact] public async Task KnockRequiresUnicastThenBroadcastThenNetworkSamePort()
 {
   var rule=Rule("R676");
   Assert.False((await rule.EvaluateAsync(At(Tcp(dport:22),0))).Matched);
   Assert.False((await rule.EvaluateAsync(At(Tcp(destination:"10.1.2.255",dport:22),1))).Matched);
   Assert.True((await rule.EvaluateAsync(At(Tcp(destination:"10.1.2.0",dport:22),2))).Matched);
   var wrong=Rule("R676");
   Assert.False((await wrong.EvaluateAsync(At(Tcp(destination:"10.1.2.255",dport:22),0))).Matched);
   Assert.False((await wrong.EvaluateAsync(At(Tcp(destination:"10.1.2.0",dport:22),1))).Matched);
   Assert.False((await wrong.EvaluateAsync(At(Tcp(destination:"10.1.2.10",dport:22),2))).Matched);
 }
 [Fact] public async Task KnockDifferentPortAndStaleTimestampFail()
 {
   var rule=Rule("R676");
   Assert.False((await rule.EvaluateAsync(At(Tcp(dport:22),0))).Matched);
   Assert.False((await rule.EvaluateAsync(At(Tcp(destination:"10.1.2.255",dport:443),1))).Matched);
   Assert.False((await rule.EvaluateAsync(At(Tcp(destination:"10.1.2.0",dport:22),2))).Matched);
   Assert.False((await rule.EvaluateAsync(At(Tcp(destination:"10.1.2.255",dport:22),-1))).Matched);
 }
 [Fact] public async Task TlsOnDnsOrAlternateHttpPortRequiresParserFields()
 {
   var t=Tcp("10.1.2.20","8.8.8.8",53000,53);t.L4Len=150;t.Length=200;t.TlsVersion="TLS1.3";t.Sni="remote.example";
   Assert.True((await Rule("R677").EvaluateAsync(At(t))).Matched);
   var standard=Tcp("10.1.2.20","8.8.8.8",53000,443);standard.L4Len=150;standard.TlsVersion="TLS1.3";standard.Sni="remote.example";
   Assert.False((await Rule("R677").EvaluateAsync(At(standard))).Matched);
   var dns=Tcp("10.1.2.20","8.8.8.8",53000,53);dns.L4Len=150;dns.TlsVersion="TLS1.3";dns.Sni="remote.example";dns.ApplicationProtocol="DNS";
   Assert.False((await Rule("R677").EvaluateAsync(At(dns))).Matched);
 }
 [Fact] public async Task IcmpSequentialWalkAndNearMiss()
 {
   var rule=Rule("R678");
   Assert.False((await rule.EvaluateAsync(At(Icmp("10.1.2.10")))).Matched);
   Assert.False((await rule.EvaluateAsync(At(Icmp("10.1.2.11"),1))).Matched);
   Assert.True((await rule.EvaluateAsync(At(Icmp("10.1.2.12"),2))).Matched);
   var wrong=Rule("R678");
   Assert.False((await wrong.EvaluateAsync(At(Icmp("10.1.2.10")))).Matched);
   Assert.False((await wrong.EvaluateAsync(At(Icmp("10.1.2.12"),1))).Matched);
   Assert.False((await wrong.EvaluateAsync(At(Icmp("10.1.2.11"),2))).Matched);
 }
 [Fact] public async Task IcsSynAckIsNotClientSynOrInternalOnly()
 {
   var reply=Tcp("10.1.2.40","8.8.8.8",502,54000,0x12);
   Assert.True((await Rule("R679").EvaluateAsync(At(reply))).Matched);
   Assert.False((await Rule("R679").EvaluateAsync(At(Tcp("10.1.2.40","8.8.8.8",502,54000,0x02)))).Matched);
   Assert.False((await Rule("R679").EvaluateAsync(At(Tcp("10.1.2.40","10.1.2.30",502,54000,0x12)))).Matched);
   Assert.False((await Rule("R679").EvaluateAsync(At(Tcp("10.1.2.40","8.8.8.8",5900,54000,0x12)))).Matched);
 }
 [Fact] public async Task InternalProcessFanoutRequiresThreePrivatePeerHosts()
 {
   var rule=Rule("R680");
   Assert.False((await rule.EvaluateAsync(At(ProcessSyn("10.1.2.10")))).Matched);
   Assert.False((await rule.EvaluateAsync(At(ProcessSyn("10.1.2.11"),1))).Matched);
   Assert.True((await rule.EvaluateAsync(At(ProcessSyn("10.1.2.12"),2))).Matched);
   Assert.False((await Rule("R680").EvaluateAsync(At(ProcessSyn("8.8.8.8")))).Matched);
   Assert.False((await Rule("R680").EvaluateAsync(At(ProcessSyn("10.1.2.10","chrome.exe")))).Matched);
 }
 [Fact] public async Task ExternalProxyPortTwoPeersAndPidGate()
 {
   var rule=Rule("R681");
   Assert.False((await rule.EvaluateAsync(At(ProcessSyn("8.8.8.8")))).Matched);
   Assert.True((await rule.EvaluateAsync(At(ProcessSyn("9.9.9.9"),1))).Matched);
   var noPid=ProcessSyn("8.8.8.8");noPid.ProcessId=0;
   Assert.False((await Rule("R681").EvaluateAsync(At(noPid))).Matched);
   Assert.False((await Rule("R681").EvaluateAsync(At(ProcessSyn("10.1.2.10")))).Matched);
 }
 [Fact] public async Task HttpHeartbeatNeedsThreeCadencedGetsFromRundll32()
 {
   var rule=Rule("R682");
   Assert.False((await rule.EvaluateAsync(At(Http("GET","/api/v1/heartbeat"),0))).Matched);
   Assert.False((await rule.EvaluateAsync(At(Http("GET","/api/v1/heartbeat"),15))).Matched);
   Assert.True((await rule.EvaluateAsync(At(Http("GET","/api/v1/heartbeat"),30))).Matched);
   Assert.False((await Rule("R682").EvaluateAsync(At(Http("POST","/api/v1/heartbeat")))).Matched);
   var chrome=Http("GET","/api/v1/heartbeat");chrome.ProcessName="chrome.exe";
   Assert.False((await Rule("R682").EvaluateAsync(At(chrome))).Matched);
 }
 [Fact] public async Task MismatchedHttpPostOnModbusPortRequiresActualHttpParser()
 {
   Assert.True((await Rule("R683").EvaluateAsync(At(Http("POST","/api/debug",dport:502)))).Matched);
   Assert.False((await Rule("R683").EvaluateAsync(At(Http("POST","/api/debug",dport:8080)))).Matched);
   var modbus=Http("POST","/api/debug",dport:502);modbus.ApplicationProtocol="modbus";
   Assert.False((await Rule("R683").EvaluateAsync(At(modbus))).Matched);
   Assert.False((await Rule("R683").EvaluateAsync(At(Http("GET","/api/debug",dport:502)))).Matched);
 }
 [Fact] public async Task OpcUaPortExchangeRequiresBothSidesSameTcpTuple()
 {
   var rule=Rule("R684");
   Assert.False((await rule.EvaluateAsync(At(Tcp("8.8.8.8","10.1.2.40",55000,4840),0))).Matched);
   Assert.True((await rule.EvaluateAsync(At(Tcp("10.1.2.40","8.8.8.8",4840,55000,0x12),1))).Matched);
   var isolated=Rule("R684");
   Assert.False((await isolated.EvaluateAsync(At(Tcp("10.1.2.40","8.8.8.8",4840,55000,0x12),0))).Matched);
   Assert.False((await isolated.EvaluateAsync(At(Tcp("8.8.8.8","10.1.2.40",55000,4840),1))).Matched);
 }
 [Fact] public async Task LargeS7RepliesFromThreeDevicesNotClientRequests()
 {
   TrafficRecord Reply(int octet)
   {
     var r=Tcp("10.4.2."+octet,"10.1.2.20",102,53000,0x18);
     r.L4Len=750;r.Length=810;r.ApplicationProtocol="s7comm";return r;
   }
   var rule=Rule("R685");
   Assert.False((await rule.EvaluateAsync(At(Reply(10)))).Matched);
   Assert.False((await rule.EvaluateAsync(At(Reply(11),1))).Matched);
   Assert.True((await rule.EvaluateAsync(At(Reply(12),2))).Matched);
   var small=Reply(10);small.L4Len=80;
   Assert.False((await Rule("R685").EvaluateAsync(At(small))).Matched);
   var wrong=Reply(10);wrong.ApplicationProtocol="modbus";
   Assert.False((await Rule("R685").EvaluateAsync(At(wrong))).Matched);
 }
 [Theory]
 [InlineData("R676")]
 [InlineData("R677")]
 [InlineData("R678")]
 [InlineData("R679")]
 [InlineData("R680")]
 [InlineData("R681")]
 [InlineData("R682")]
 [InlineData("R683")]
 [InlineData("R684")]
 [InlineData("R685")]
 public void ExactlyOneRegisteredCandidateShadow(string id)
 {
    var rule=Assert.Single(RuleRegistry.CreateDefaultRules().Where(r=>r.Descriptor.RuleId==id));
    var p=Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(rule);
    Assert.Equal(RulePrecisionMaturity.Candidate,p.PrecisionProfile.Maturity);
    Assert.Equal(RuleRuntimeMode.Shadow,p.PrecisionProfile.DefaultMode);
 }
 [Fact] public async Task DuplicateIdsAndCooldownCannotEmitRepeatedEvents()
 {
    var rule=Rule("R677");
    TrafficRecord Make()
    {
      var r=Tcp("10.1.2.20","8.8.8.8",53000,53);r.L4Len=160;r.Length=200;
      r.TlsVersion="TLS1.3";r.Sni="service.example";return r;
    }
    var first=Make();
    var ev=Assert.Single((await rule.EvaluateAsync(At(first,10))).Events);
    var json=JsonSerializer.Serialize(ev);
    Assert.Contains("nonstandard_tls_port_only_unknown",json);
    Assert.False((await rule.EvaluateAsync(At(first,11))).Matched);
    Assert.False((await rule.EvaluateAsync(At(Make(),9))).Matched);
    var suppressed=await rule.EvaluateAsync(At(Make(),12));
    Assert.True(suppressed.Suppressed);Assert.Empty(suppressed.Events);
    Assert.True((await rule.EvaluateAsync(At(Make(),611))).Matched);
 }
}
