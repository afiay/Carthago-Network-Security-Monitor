// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, 0 executed. Workbook R1371.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Independent Regular-size outbound TCP payload sequence from an attributed process; no success, identity or exfiltration inference.</summary>
 public sealed class R658_UniformIntervalOutboundProcessTcpPayloadSequenceRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
     RuleId:"R658",Name:"Regular-size outbound TCP payload sequence from an attributed process",Category:"ExfiltrationAdvanced",
     Description:"Regular-size outbound TCP payload sequence from an attributed process. R254 counts repeated declared HTTP uploads; this matches four non-HTTP TCP payload observations with constrained lengths and spacing, without transfer claims.",
     DefaultSeverity:SeverityLevel.Low,
     ConfigKey:"Rules.R658.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R658",Name="Regular-size outbound TCP payload sequence from an attributed process",Category="ExfiltrationAdvanced",Description="R254 counts repeated declared HTTP uploads; this matches four non-HTTP TCP payload observations with constrained lengths and spacing, without transfer claims.",
     Severity=SeverityLevel.Low,
     Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Process},
     RequiredFields=new[]{"source","destination_or_host","process.name","process.id","network.destinationPort"},
     EvidenceFields=new[]{"research.identifier","matched_conditions","outcome"},
     PositiveConditions=new[]{
       "Require observed typed source/destination and the individual workbook-derived predicate.",
       "Process/PID association is best-effort and does not establish authenticated executable identity.",
       "Request, query, port probe and connection-shape outcomes remain unverified."
     },
     NegativeConditions=new[]{
       "Reject missing or conflicting protocol, wrong method or port, or unparsed Info-only assertions.",
       "Reject unrelated benign near misses, duplicate IDs, stale timestamps, and cooldown repeats.",
       "Do not infer credential disclosure, exfiltration, successful Git push, authentication, or tunnel setup."
     },
     FalsePositives=new[]{"Authorized developer workflows, management clients, automated scripts or normal network operations may match. R254 counts repeated declared HTTP uploads; this matches four non-HTTP TCP payload observations with constrained lengths and spacing, without transfer claims."},
     MinimumConfidence=80,
     WindowThreshold=4,
     Window=TimeSpan.FromMinutes(5),Cooldown=TimeSpan.FromMinutes(10),
     DistinctBy="specific_rule_process_peer_tuple_or_bounded_sequence",
     TuningKnobs=new[]{"Mode","ApprovedHosts","ApprovedMaintenanceWindows","ApprovedProcesses"},
     RequiredTests=new[]{
       "positive evidence and rule-specific benign near miss",
       "wrong/missing parser or process fields; public/private boundary",
       "duplicate observations and out-of-order timestamps",
       "expiry and bounded state; cooldown; fixed evidence privacy",
       "Shadow Candidate and unique sequential registry"
     }
   });
   private readonly WebSignatureCooldown _cooldown=new();
   private readonly Research656UniformWindow _uniform=new();
   public R658_UniformIntervalOutboundProcessTcpPayloadSequenceRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!NetworkBatch266270Evidence.ProcessEgress(r,out var process)
||r.HttpMethod!=null||r.DnsQname!=null||r.TlsVersion!=null
||r.L4Len is null or <700 or >1400
||!_uniform.Observe(r.Source+"|"+r.Destination+"|"+r.ProcessId+"|"+process,
r.Id,r.L4Len.Value,context.TimestampUtc))
return NoMatch();
     var seen=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(seen==WebSignatureObservation.None)return NoMatch();
     if(seen==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1371","owner-research"),
       new DetectionEvidenceItem("matched_conditions","uniform_shape","rule"),
       new DetectionEvidenceItem("outcome","uniform_tcp_payload_observation_only","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Low,
       "Regular-size outbound TCP payload sequence from an attributed process observed; response, authorization and security outcome unknown",
       evidence,c=>{
         c.AddEvidence(0.43,"typed-producer-input");
         c.AddEvidence(0.35,"independent-workbook-predicate");
         c.AddCorrelation(0.12,"coherent-observation");
       },count:4,windowSeconds:300);
     
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
   
 }
}
