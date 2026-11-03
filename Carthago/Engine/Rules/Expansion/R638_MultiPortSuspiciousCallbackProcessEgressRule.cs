// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed. Workbook R2190.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
  /// <summary>Independent workbook R2190 candidate; no exploitation, outcome, or actor attribution.</summary>
  public sealed class R638_MultiPortSuspiciousCallbackProcessEgressRule : EvidenceDrivenPrecisionRuleBase
  {
    private static readonly RuleDescriptor Rule = new(
      RuleId:"R638",Name:"Process outbound TCP contact across multiple callback-associated ports",Category:"EvasionInfra",
      Description:"Process outbound TCP contact across multiple callback-associated ports. Observed evidence only; The workbook's Linux log producer is absent; only a best-effort locally attributed Windows TCP-flow analogue is implemented. Distinct port contact is not confirmed malware.",
      DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R638.Enabled",EnabledByDefault:true);
    private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
    {
      RuleId="R638",Name="Process outbound TCP contact across multiple callback-associated ports",Category="EvasionInfra",
      Description="Source-only candidate from R2190: The workbook's Linux log producer is absent; only a best-effort locally attributed Windows TCP-flow analogue is implemented. Distinct port contact is not confirmed malware.",
      Severity=SeverityLevel.Medium,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
      RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Process},
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
      FalsePositives=new[]{"The workbook's Linux log producer is absent; only a best-effort locally attributed Windows TCP-flow analogue is implemented. Distinct port contact is not confirmed malware."},
      MinimumConfidence=82,WindowThreshold=2,
      Window=TimeSpan.FromMinutes(5),Cooldown=TimeSpan.FromMinutes(10),
      DistinctBy="rule_specific_typed_observation_exact_peer_or_bounded_window",
      TuningKnobs=new[]{"Mode","ApprovedAdminHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
      RequiredTests=new[]{"exact positive and benign near miss","missing/contradictory protocol or metadata",
        "duplicate IDs, expired time, cooldown","safe redacted evidence and honest scope",
        "candidate shadow policy, independent registry registration"}
    });
    private readonly WebSignatureCooldown _cooldown=new();
    public R638_MultiPortSuspiciousCallbackProcessEgressRule():base(Rule,Profile){}

    protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
    {
      var r=context.Record;
      if(!ProcessSignatureEvidence.TryExternalTcp(r,out var name)||!Specific(r,name)||!PairOfPorts(r,name,context.TimestampUtc))return NoMatch();
      var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
      if(observed==WebSignatureObservation.None)return NoMatch();
      if(observed==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
      var evidence=new[]
      {
        new DetectionEvidenceItem("research.identifier","workbook.R2190","source-research"),
        new DetectionEvidenceItem("matched_conditions","independent_multiport_predicate","rule"),
        new DetectionEvidenceItem("outcome","multi_port_candidate_only_unknown","rule")
      };
      var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
        "Observed Process outbound TCP contact across multiple callback-associated ports; no authenticated outcome established",
        evidence,confidence=>{
          confidence.AddEvidence(0.45,"bounded-observed-multiport-metadata");
          confidence.AddEvidence(0.34,"specific-workbook-shape");
          confidence.AddCorrelation(0.12,"coherent-typed-observation");
        },count:2,windowSeconds:300);
      
      return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
    }
    private static bool Specific(TrafficRecord r,string name){return name is not ("chrome.exe" or "firefox.exe" or "msedge.exe" or "svchost.exe") && r.DestinationPort is 888 or 999 or 2200 or 2222 or 4000 or 4444 or 6789 or 8531 or 50501;}private sealed class Slot{internal readonly HashSet<int> Ports=new();internal readonly HashSet<Guid> Seen=new();internal DateTime Latest=DateTime.MinValue;internal DateTime First;}
private readonly Dictionary<string,Slot> _slots=new(StringComparer.Ordinal);
private readonly object _gate=new();
private bool PairOfPorts(TrafficRecord r,string process,DateTime at){
 if(at.Kind!=DateTimeKind.Utc||r.Id==Guid.Empty||r.DestinationPort==null)return false;
 var key=r.Source+"|"+r.Destination+"|"+r.ProcessId+"|"+process;
 lock(_gate){
 if(!_slots.TryGetValue(key,out var slot)){
  if(_slots.Count>=512){foreach(var old in _slots.Where(k=>at>=k.Value.Latest && at-k.Value.Latest>TimeSpan.FromMinutes(10)).Select(k=>k.Key).ToArray())_slots.Remove(old);if(_slots.Count>=512)return false;}
  slot=new Slot{First=at};_slots.Add(key,slot);
 }
 if(at<=slot.Latest||slot.Seen.Contains(r.Id))return false;
 if(at-slot.First>TimeSpan.FromMinutes(5)){slot.Ports.Clear();slot.Seen.Clear();slot.First=at;}
 if(slot.Seen.Count>=64)return false;
 slot.Seen.Add(r.Id);slot.Latest=at;slot.Ports.Add(r.DestinationPort.Value);
 if(slot.Ports.Count<2)return false;
 slot.Ports.Clear();slot.Seen.Clear();slot.First=at;return true;
 }
}
  }
}
