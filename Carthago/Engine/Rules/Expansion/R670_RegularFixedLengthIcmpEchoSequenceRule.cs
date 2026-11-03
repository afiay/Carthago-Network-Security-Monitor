// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed. Research R2022.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Independent R2022: Four regularly spaced fixed-size ICMP echo requests.</summary>
 public sealed class R670_RegularFixedLengthIcmpEchoSequenceRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
     RuleId:"R670",Name:"Four regularly spaced fixed-size ICMP echo requests",Category:"EvasionTunnel",
     Description:"Four regularly spaced fixed-size ICMP echo requests. A regular ping sequence is often benign and does not prove C2 or tunneling.",
     DefaultSeverity:SeverityLevel.Low,ConfigKey:"Rules.R670.Enabled",
     EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R670",Name="Four regularly spaced fixed-size ICMP echo requests",Category="EvasionTunnel",
     Description="Original workbook R2022: R021 generic ICMP tunneling and R033 oversized echo detect different inputs; this requires four same-length echoes with bounded inter-arrival spacing.. A regular ping sequence is often benign and does not prove C2 or tunneling.",
     Severity=SeverityLevel.Low,
     Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow},
     RequiredFields=new[]{"source","destination_or_host","protocol_or_port","icmp.type_code","l4.length"},
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
     FalsePositives=new[]{"A regular ping sequence is often benign and does not prove C2 or tunneling. Legitimate tools and security testing can trigger this candidate."},
     MinimumConfidence=78,
     WindowThreshold=4,
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
   public R670_RegularFixedLengthIcmpEchoSequenceRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!Research666Evidence.Outbound(r)||r.IsTcp||r.IsUdp||r.IsQuic||r.IpVersion!=4
||!string.Equals(r.Protocol,"ICMP",StringComparison.OrdinalIgnoreCase)
||r.IcmpTypeCode!=0x0800||r.L4Len is null or <40 or >120
||r.HttpMethod!=null||r.DnsQname!=null
||!_timed.Observe(r.Source+"|"+r.Destination,r.Id,r.L4Len.Value,context.TimestampUtc,4,true))
return NoMatch();
     var state=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(state==WebSignatureObservation.None)return NoMatch();
     if(state==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R2022","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_icmp_predicate","rule"),
       new DetectionEvidenceItem("outcome","fixed_interval_icmp_echo_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Low,
       "Four regularly spaced fixed-size ICMP echo requests observed; process identity and security outcome unverified",
       evidence,c=>{
         c.AddEvidence(0.44,"coherent-typed-packet-metadata");
         c.AddEvidence(0.35,"distinct-workbook-signature");
         c.AddCorrelation(0.12,"bounded-network-context");
       },count:4,windowSeconds:120);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
   
 }
}
