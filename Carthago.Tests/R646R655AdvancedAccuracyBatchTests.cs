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
public sealed class R646R655AdvancedAccuracyBatchTests
{
 private static readonly DateTime Origin=new(2026,11,3,21,0,0,DateTimeKind.Utc);
 private static IDetectionRule Rule(string id)=>id switch
 {
 "R646"=>new R646_DeviceFirmwareHttpUploadAttemptRule(),
 "R647"=>new R647_MinerProcessPublicPoolPortEgressRule(),
 "R648"=>new R648_VncListenerPublicSynAckResponseRule(),
 "R649"=>new R649_WinRmListenerPublicSynAckResponseRule(),
 "R650"=>new R650_CurlWgetProcessPublicSubnetFanoutRule(),
 "R651"=>new R651_ExternalCmsContentSavePostAttemptRule(),
 "R652"=>new R652_ScriptHostFtpExternalUploadRequestRule(),
 "R653"=>new R653_PublicModbusNonWriteHostSweepRule(),
 "R654"=>new R654_PublicS7CommHostSweepRule(),
 "R655"=>new R655_PublicEtherNetIpListIdentityHostSweepRule(),
 _=>throw new ArgumentOutOfRangeException(nameof(id))
 };
 private static RuleEvaluationContext At(TrafficRecord r,int seconds=0)
  =>new(r,Sensitivity.Balanced,Origin.AddSeconds(seconds));
 private static TrafficRecord Http(string path,string method="POST",bool externalSource=false)
  =>new()
  {
    Id=Guid.NewGuid(),Source=externalSource?"8.8.8.8":"10.1.1.20",
    Destination=externalSource?"10.1.1.40":"8.8.8.8",IpVersion=4,
    Protocol="TCP",IsTcp=true,SourcePort=50001,DestinationPort=80,
    L4Len=200,Length=244,ApplicationProtocol="HTTP",HttpMethod=method,HttpUri=path,
    HttpHost="device.lab",HttpRequestHeaders="Host: device.lab\nContent-Type: application/octet-stream"
  };
 private static TrafficRecord Flow(string process,string dest="8.8.8.8",int port=3333)
  =>new()
  {
    Id=Guid.NewGuid(),Source="10.1.1.20",Destination=dest,IpVersion=4,
    Protocol="TCP",IsTcp=true,SourcePort=50111,DestinationPort=port,
    L4Len=200,Length=240,ProcessName=process,ProcessId=3456
  };
 private static TrafficRecord Response(int port,int flags=0x12,bool publicClient=true)
  =>new()
  {
    Id=Guid.NewGuid(),Source="10.1.1.40",
    Destination=publicClient?"8.8.8.8":"10.1.1.20",IpVersion=4,
    Protocol="TCP",IsTcp=true,SourcePort=port,DestinationPort=50001,
    L4Len=0,Length=40,TcpFlags=(ushort)flags
  };
 private static TrafficRecord Ot(string protocol,int service,string dest)
  =>new()
  {
    Id=Guid.NewGuid(),Source="8.8.8.8",Destination=dest,IpVersion=4,
    Protocol="TCP",IsTcp=true,SourcePort=50002,DestinationPort=service,
    L4Len=48,Length=88,ApplicationProtocol=protocol
  };
 [Fact] public async Task FirmwareUploadRequestRequiresPostBinaryHeaderAndExactPath()
 {
  var yes=Http("/firmware/upload");
  Assert.True((await Rule("R646").EvaluateAsync(At(yes))).Matched);
  Assert.False((await Rule("R646").EvaluateAsync(At(Http("/firmware/check")))).Matched);
  Assert.False((await Rule("R646").EvaluateAsync(At(Http("/firmware/upload","GET")))).Matched);
  var missing=Http("/firmware/upload");missing.HttpRequestHeaders="Host: device.lab";
  Assert.False((await Rule("R646").EvaluateAsync(At(missing))).Matched);
  var tls=Http("/firmware/upload");tls.TlsVersion="TLS1.3";
  Assert.False((await Rule("R646").EvaluateAsync(At(tls))).Matched);
 }
 [Fact] public async Task MinerRequiresExactProcessAndPoolAssociatedPort()
 {
  Assert.True((await Rule("R647").EvaluateAsync(At(Flow("xmrig.exe")))).Matched);
  Assert.False((await Rule("R647").EvaluateAsync(At(Flow("chrome.exe")))).Matched);
  Assert.False((await Rule("R647").EvaluateAsync(At(Flow("xmrig.exe",port:443)))).Matched);
  var noPid=Flow("xmrig.exe");noPid.ProcessId=0;
  Assert.False((await Rule("R647").EvaluateAsync(At(noPid))).Matched);
 }
 [Theory][InlineData("R648",5900)][InlineData("R649",5985)][InlineData("R649",5986)]
 public async Task ServerSynAckOnlyWithPublicClient(string id,int port)
 {
  Assert.True((await Rule(id).EvaluateAsync(At(Response(port)))).Matched);
  Assert.False((await Rule(id).EvaluateAsync(At(Response(port,0x02)))).Matched);
  Assert.False((await Rule(id).EvaluateAsync(At(Response(port,0x12,false)))).Matched);
  var http=Response(port);http.HttpMethod="GET";
  Assert.False((await Rule(id).EvaluateAsync(At(http))).Matched);
 }
 [Fact] public async Task CurlWgetPublicSubnetFanoutUsesSameProcessAndDistinctNetworks()
 {
  var rule=Rule("R650");
  Assert.False((await rule.EvaluateAsync(At(Flow("curl.exe","8.8.8.8",443)))).Matched);
  Assert.False((await rule.EvaluateAsync(At(Flow("curl.exe","8.8.8.9",443),1))).Matched);
  Assert.False((await rule.EvaluateAsync(At(Flow("curl.exe","9.9.9.9",443),2))).Matched);
  Assert.True((await rule.EvaluateAsync(At(Flow("curl.exe","1.1.1.1",443),3))).Matched);
 }
 [Fact] public async Task CurlWgetMixedProcessesAndOutOfOrderCannotCombine()
 {
  var rule=Rule("R650");
  Assert.False((await rule.EvaluateAsync(At(Flow("curl.exe","8.8.8.8")))).Matched);
  Assert.False((await rule.EvaluateAsync(At(Flow("wget.exe","9.9.9.9"),1))).Matched);
  Assert.False((await rule.EvaluateAsync(At(Flow("curl.exe","1.1.1.1"),2))).Matched);
  Assert.False((await rule.EvaluateAsync(At(Flow("curl.exe","4.4.4.4"),1))).Matched);
 }
 [Fact] public async Task ExternalCmsContentSavePostRequiresAdminPathAndForm()
 {
  var valid=Http("/admin/content/save",externalSource:true);
  valid.HttpRequestHeaders="Host: cms.lab\nContent-Type: application/json";
  Assert.True((await Rule("R651").EvaluateAsync(At(valid))).Matched);
  var benign=Http("/admin/login",externalSource:true);
  benign.HttpRequestHeaders=valid.HttpRequestHeaders;
  Assert.False((await Rule("R651").EvaluateAsync(At(benign))).Matched);
  var internalFlow=Http("/admin/content/save");internalFlow.HttpRequestHeaders=valid.HttpRequestHeaders;
  Assert.False((await Rule("R651").EvaluateAsync(At(internalFlow))).Matched);
 }
 [Fact] public async Task ScriptHostFtpUploadRequiresTypedStorAndLocalPid()
 {
  var r=Flow("wscript.exe","8.8.8.8",21);
  r.ApplicationProtocol="ftp.stor";
  Assert.True((await Rule("R652").EvaluateAsync(At(r))).Matched);
  var list=Flow("wscript.exe","8.8.8.8",21);list.ApplicationProtocol="ftp.list";
  Assert.False((await Rule("R652").EvaluateAsync(At(list))).Matched);
  var backup=Flow("winscp.exe","8.8.8.8",21);backup.ApplicationProtocol="ftp.stor";
  Assert.False((await Rule("R652").EvaluateAsync(At(backup))).Matched);
  var noPid=Flow("wscript.exe","8.8.8.8",21);noPid.ApplicationProtocol="ftp.stor";noPid.ProcessId=0;
  Assert.False((await Rule("R652").EvaluateAsync(At(noPid))).Matched);
 }
 [Theory][InlineData("R653","modbus",502)][InlineData("R654","s7comm",102)]
 [InlineData("R655","ethernetip.listidentity",44818)]
 public async Task PublicOtHostSweepThreeUniqueHostsSame24(string id,string protocol,int port)
 {
  var rule=Rule(id);
  Assert.False((await rule.EvaluateAsync(At(Ot(protocol,port,"10.2.1.10")))).Matched);
  Assert.False((await rule.EvaluateAsync(At(Ot(protocol,port,"10.2.1.11"),1))).Matched);
  var done=await rule.EvaluateAsync(At(Ot(protocol,port,"10.2.1.12"),2));
  Assert.True(done.Matched);Assert.Equal(id,Assert.Single(done.Events).RuleId);
 }
 [Theory][InlineData("R653","modbus",502)][InlineData("R654","s7comm",102)]
 [InlineData("R655","ethernetip.listidentity",44818)]
 public async Task OtMixedSubnetsSameHostAndContradictoryMetadataAreNegative(string id,string protocol,int port)
 {
  var rule=Rule(id);
  Assert.False((await rule.EvaluateAsync(At(Ot(protocol,port,"10.2.1.10")))).Matched);
  Assert.False((await rule.EvaluateAsync(At(Ot(protocol,port,"10.2.1.10"),1))).Matched);
  Assert.False((await rule.EvaluateAsync(At(Ot(protocol,port,"10.2.2.11"),2))).Matched);
  var different=Ot(protocol,port,"10.2.1.12");different.Source="9.9.9.9";
  Assert.False((await rule.EvaluateAsync(At(different,3))).Matched);
  var dns=Ot(protocol,port,"10.2.1.13");dns.DnsQname="forged.invalid";
  Assert.False((await rule.EvaluateAsync(At(dns,4))).Matched);
  var write=Ot("modbus.write",502,"10.2.1.14");
  if(id=="R653")Assert.False((await rule.EvaluateAsync(At(write,5))).Matched);
 }
 [Fact] public async Task FixedEvidenceDoesNotContainPrivateUriOrProcessPath()
 {
  var r=Http("/firmware/upload");r.Info="classified secret payload";
  var evt=Assert.Single((await Rule("R646").EvaluateAsync(At(r))).Events);
  var encoded=JsonSerializer.Serialize(evt);
  Assert.DoesNotContain("classified secret payload",encoded);
  Assert.Contains("firmware_request_only_unknown",encoded);
 }
 [Theory][InlineData("R646")][InlineData("R647")][InlineData("R648")][InlineData("R649")]
 [InlineData("R650")][InlineData("R651")][InlineData("R652")][InlineData("R653")]
 [InlineData("R654")][InlineData("R655")]
 public void RegistryHasIndependentShadowCandidate(string id)
 {
  var registered=Assert.Single(RuleRegistry.CreateDefaultRules().Where(r=>r.Descriptor.RuleId==id));
  var p=Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(registered);
  Assert.Equal(RuleRuntimeMode.Shadow,p.PrecisionProfile.DefaultMode);
  Assert.Equal(RulePrecisionMaturity.Candidate,p.PrecisionProfile.Maturity);
 }
 [Fact] public async Task DuplicateIdStaleTimeAndCooldownCannotGenerateAnotherMatch()
 {
   var rule=Rule("R647");var first=Flow("xmrig.exe");
   Assert.True((await rule.EvaluateAsync(At(first,10))).Matched);
   Assert.False((await rule.EvaluateAsync(At(first,11))).Matched);
   Assert.False((await rule.EvaluateAsync(At(Flow("xmrig.exe"),9))).Matched);
   var suppressed=await rule.EvaluateAsync(At(Flow("xmrig.exe"),12));
   Assert.True(suppressed.Suppressed);Assert.Empty(suppressed.Events);
   Assert.True((await rule.EvaluateAsync(At(Flow("xmrig.exe"),611))).Matched);
 }
}
