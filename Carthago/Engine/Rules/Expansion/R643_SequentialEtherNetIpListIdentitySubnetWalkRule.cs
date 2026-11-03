// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed. Workbook R2707.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
  /// <summary>Independent workbook R2707 candidate; no exploitation, outcome, or actor attribution.</summary>
  public sealed class R643_SequentialEtherNetIpListIdentitySubnetWalkRule : EvidenceDrivenPrecisionRuleBase
  {
    private static readonly RuleDescriptor Rule = new(
      RuleId:"R643",Name:"Sequential EtherNet/IP ListIdentity private-subnet discovery walk",Category:"OtIcsDeep",
      Description:"Sequential EtherNet/IP ListIdentity private-subnet discovery walk. Observed evidence only; Does not establish PLC identity, authorized engineer inventory, full subnet scan or unauthorized access. Capture can miss packets and suppress a true walk.",
      DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R643.Enabled",EnabledByDefault:true);
    private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
    {
      RuleId="R643",Name="Sequential EtherNet/IP ListIdentity private-subnet discovery walk",Category="OtIcsDeep",
      Description="Source-only candidate from R2707: Does not establish PLC identity, authorized engineer inventory, full subnet scan or unauthorized access. Capture can miss packets and suppress a true walk.",
      Severity=SeverityLevel.Medium,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
      RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.OtIcsProtocol},
      RequiredFields=new[]{"source","destination_or_host","protocol_or_port","process.name","process.id"},
      EvidenceFields=new[]{"matched_conditions","research.identifier","outcome"},
      PositiveConditions=new[]
      {
        "Only typed packet metadata and this rule's independent exact predicate can satisfy the candidate.",
        "Use parser-backed HTTP/DNS/OT fields or explicitly conditional process/TCP metadata, with coherent endpoints.",
        "An observed request, query, connection attempt or SYN-ACK is not an authenticated security outcome."
      },
      NegativeConditions=new[]
      {
        "Reject missing producer fields, contradictory transport, generic port-only or Info-only evidence.",
        "Reject benign near misses, packet duplicates, stale time and cooldown repeats.",
        "Never claim successful exploitation, credential disclosure, actor attribution or established tunnel."
      },
      FalsePositives=new[]{"Does not establish PLC identity, authorized engineer inventory, full subnet scan or unauthorized access. Capture can miss packets and suppress a true walk."},
      MinimumConfidence=84,WindowThreshold=3,
      Window=TimeSpan.FromMinutes(5),Cooldown=TimeSpan.FromMinutes(10),
      DistinctBy="rule_specific_typed_observation_exact_peer_or_bounded_window",
      TuningKnobs=new[]{"Mode","ApprovedAdminHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
      RequiredTests=new[]{"exact positive and benign near miss","missing/contradictory protocol or metadata",
        "duplicate IDs, expired time, cooldown","safe redacted evidence and honest scope",
        "candidate shadow policy, independent registry registration"}
    });
    private readonly WebSignatureCooldown _cooldown=new();
    public R643_SequentialEtherNetIpListIdentitySubnetWalkRule():base(Rule,Profile){}

    protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
    {
      var r=context.Record;
      if(!Specific(r,out var key,out var octet)||!SequentialTargets(r,key,octet,context.TimestampUtc))return NoMatch();
      var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
      if(observed==WebSignatureObservation.None)return NoMatch();
      if(observed==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
      var evidence=new[]
      {
        new DetectionEvidenceItem("research.identifier","workbook.R2707","source-research"),
        new DetectionEvidenceItem("matched_conditions","independent_otwalk_predicate","rule"),
        new DetectionEvidenceItem("outcome","ot_sequential_discovery_only_unknown","rule")
      };
      var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
        "Observed Sequential EtherNet/IP ListIdentity private-subnet discovery walk; no authenticated outcome established",
        evidence,confidence=>{
          confidence.AddEvidence(0.45,"bounded-observed-otwalk-metadata");
          confidence.AddEvidence(0.34,"specific-workbook-shape");
          confidence.AddCorrelation(0.12,"coherent-typed-observation");
        },count:3,windowSeconds:300);
      
      return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
    }
    private static bool Specific(TrafficRecord r,out string key,out int octet){
 key=string.Empty;octet=0;
 if(r.Id==Guid.Empty||r.IpVersion!=4||!r.IsTcp||r.IsUdp||r.IsQuic||r.DestinationPort!=44818
 ||r.SourcePort is null or <=0 or >65535||r.L4Len is null or <24 or >4096||r.Length<40
 ||!string.Equals(r.Protocol,"TCP",StringComparison.OrdinalIgnoreCase)
 ||!string.Equals(r.ApplicationProtocol,"ethernetip.listidentity",StringComparison.Ordinal)
 ||r.HttpMethod!=null||r.DnsQname!=null||r.TlsVersion!=null
 ||!IPAddress.TryParse(r.Source,out var source)||!IPAddress.TryParse(r.Destination,out var dest)
 ||!Private(source)||!Private(dest))return false;
 var b=dest.GetAddressBytes();octet=b[3];key=source+"|"+b[0]+"."+b[1]+"."+b[2];
 return true;
 }private static bool Private(IPAddress a){if(a.AddressFamily!=AddressFamily.InterNetwork)return false;var b=a.GetAddressBytes();return b[0]==10||(b[0]==172&&b[1]>=16&&b[1]<=31)||(b[0]==192&&b[1]==168);}
private static bool Public(IPAddress a){if(a.AddressFamily!=AddressFamily.InterNetwork)return false;var b=a.GetAddressBytes();return b[0]!=0&&b[0]!=10&&b[0]!=127&&b[0]<224&&!(b[0]==169&&b[1]==254)&&!(b[0]==100&&b[1]>=64&&b[1]<=127)&&!(b[0]==172&&b[1]>=16&&b[1]<=31)&&!(b[0]==192&&(b[1]==168||b[1]==0||b[1]==88&&b[2]==99))&&!(b[0]==198&&(b[1]==18||b[1]==19||b[1]==51&&b[2]==100))&&!(b[0]==203&&b[1]==0&&b[2]==113);}
private sealed class Slot{internal int Last=-1;internal int Count;internal DateTime First,Latest;internal readonly HashSet<Guid> Seen=new();}
private readonly Dictionary<string,Slot> _slots=new(StringComparer.Ordinal);
private readonly object _gate=new();
private bool SequentialTargets(TrafficRecord r,string key,int octet,DateTime at){
 if(at.Kind!=DateTimeKind.Utc||r.Id==Guid.Empty)return false;
 lock(_gate){
 if(!_slots.TryGetValue(key,out var slot)){
  if(_slots.Count>=512){foreach(var old in _slots.Where(k=>at>=k.Value.Latest && at-k.Value.Latest>TimeSpan.FromMinutes(10)).Select(k=>k.Key).ToArray())_slots.Remove(old);if(_slots.Count>=512)return false;}
  slot=new Slot{First=at};_slots.Add(key,slot);
 }
 if(at<=slot.Latest||slot.Seen.Contains(r.Id))return false;
 if(at-slot.First>TimeSpan.FromMinutes(5)||octet!=slot.Last+1){slot.Count=0;slot.Seen.Clear();slot.First=at;}
 if(slot.Seen.Count>=64)return false;
 slot.Seen.Add(r.Id);slot.Last=octet;slot.Latest=at;slot.Count++;
 if(slot.Count<3)return false;
 slot.Count=0;slot.Seen.Clear();slot.First=at;return true;
 }
}
  }
}
