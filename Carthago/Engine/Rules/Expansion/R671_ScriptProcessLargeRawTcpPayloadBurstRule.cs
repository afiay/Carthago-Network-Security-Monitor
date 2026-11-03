// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed. Research R2056.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Independent R2056: Eight large raw TCP payload observations from an attributed script process.</summary>
 public sealed class R671_ScriptProcessLargeRawTcpPayloadBurstRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
     RuleId:"R671",Name:"Eight large raw TCP payload observations from an attributed script process",Category:"ExfiltrationAdvanced",
     Description:"Eight large raw TCP payload observations from an attributed script process. Observed packet payload length is not directional application bytes, delivery, data content or demonstrated junk traffic.",
     DefaultSeverity:SeverityLevel.Low,ConfigKey:"Rules.R671.Enabled",
     EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R671",Name="Eight large raw TCP payload observations from an attributed script process",Category="ExfiltrationAdvanced",
     Description="Original workbook R2056: R658 detects uniform moderate-size timed observations; this requires repeated large non-HTTP/non-TLS payload packets on uncommon ports.. Observed packet payload length is not directional application bytes, delivery, data content or demonstrated junk traffic.",
     Severity=SeverityLevel.Low,
     Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Process},
     RequiredFields=new[]{"source","destination_or_host","protocol_or_port","process.id","tcp.flags_or_payload"},
     EvidenceFields=new[]{"research.identifier","matched_conditions","outcome"},
     PositiveConditions=new[]{
       "The packet/flow must have coherent typed producer metadata and a specific independent rule predicate.",
       "Every process attribution is best-effort local tuple correlation, not an authenticated process event.",
       "Only request, handshake, packet, or flow observation is established, never security outcome."
     },
     NegativeConditions=new[]{
       "No port-only or Info-only proxy for a required packet parser field.",
       "Reject missing/contradictory transport fields, unrelated benign near-misses and forged source context.",
       "Reject duplicate IDs, out-of-order observations and cooldown repeats; never infer compromise."
     },
     FalsePositives=new[]{"Observed packet payload length is not directional application bytes, delivery, data content or demonstrated junk traffic. Legitimate tools and security testing can trigger this candidate."},
     MinimumConfidence=80,
     WindowThreshold=8,
     Window=TimeSpan.FromMinutes(2),Cooldown=TimeSpan.FromMinutes(10),
     DistinctBy="source_peer_and_independent_signature_or_sequence",
     TuningKnobs=new[]{"Mode","ApprovedProcesses","ApprovedMaintenanceWindows","ApprovedDestinations"},
     RequiredTests=new[]{"positive typed sample and benign negative","missing producer and contradictory fields",
       "independent thresholds, duplicate/out-of-order/expiration and cooldown",
       "redacted evidence/no sensitive payload or asserted security outcome",
       "Candidate Shadow mode and registry uniqueness"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   private readonly Research666TimedWindow _timed=new();
   public R671_ScriptProcessLargeRawTcpPayloadBurstRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!NetworkBatch266270Evidence.ProcessEgress(r,out var p)
||p is not ("powershell.exe" or "pwsh.exe" or "python.exe" or "rundll32.exe")
||r.DestinationPort is null or <=1024 or 1883 or 3306 or 3389 or 5432 or 6379 or 8080 or 8443
||r.HttpMethod!=null||r.DnsQname!=null||r.TlsVersion!=null
||r.L4Len is null or <1500 or >4096
||!_timed.Observe(r.Source+"|"+r.Destination+"|"+r.ProcessId+"|"+p,
r.Id,r.L4Len.Value,context.TimestampUtc,8,false,12000))
return NoMatch();
     var state=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(state==WebSignatureObservation.None)return NoMatch();
     if(state==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R2056","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_rawburst_predicate","rule"),
       new DetectionEvidenceItem("outcome","raw_tcp_payload_burst_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Low,
       "Eight large raw TCP payload observations from an attributed script process observed; process identity and security outcome unverified",
       evidence,c=>{
         c.AddEvidence(0.44,"coherent-typed-packet-metadata");
         c.AddEvidence(0.35,"distinct-workbook-signature");
         c.AddCorrelation(0.12,"bounded-network-context");
       },count:8,windowSeconds:120);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
   
 }
}
