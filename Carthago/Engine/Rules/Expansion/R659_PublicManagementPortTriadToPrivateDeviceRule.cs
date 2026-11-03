// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, 0 executed. Workbook R1808.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Independent Public client probing SNMP, NETCONF, and HTTPS management ports; no success, identity or exfiltration inference.</summary>
 public sealed class R659_PublicManagementPortTriadToPrivateDeviceRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
     RuleId:"R659",Name:"Public client probing SNMP, NETCONF, and HTTPS management ports",Category:"NetworkApplianceExposure",
     Description:"Public client probing SNMP, NETCONF, and HTTPS management ports. R585 tracks a triad of parsed administrative operations, not this exact cross-transport SNMP/NETCONF/HTTPS port triad.",
     DefaultSeverity:SeverityLevel.Medium,
     ConfigKey:"Rules.R659.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R659",Name="Public client probing SNMP, NETCONF, and HTTPS management ports",Category="NetworkApplianceExposure",Description="R585 tracks a triad of parsed administrative operations, not this exact cross-transport SNMP/NETCONF/HTTPS port triad.",
     Severity=SeverityLevel.Medium,
     Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow},
     RequiredFields=new[]{"source","destination_or_host","network.destinationPort","source","destination"},
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
     FalsePositives=new[]{"Authorized developer workflows, management clients, automated scripts or normal network operations may match. R585 tracks a triad of parsed administrative operations, not this exact cross-transport SNMP/NETCONF/HTTPS port triad."},
     MinimumConfidence=80,
     WindowThreshold=3,
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
   private readonly Research656DistinctWindow _distinct=new();
   public R659_PublicManagementPortTriadToPrivateDeviceRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!Research646Evidence.Pair(r,true,out _,out _)
||r.SourcePort is null or <=0 or >65535 ||r.DestinationPort is null
||r.IsQuic ||r.HttpMethod!=null ||r.DnsQname!=null
||!((r.IsUdp&&!r.IsTcp&&r.Protocol=="UDP"&&r.DestinationPort==161&&r.L4Len is >0 and <=1200)
||(r.IsTcp&&!r.IsUdp&&r.Protocol=="TCP"&&r.DestinationPort is 830 or 443)))
return NoMatch();
if(!_distinct.Observe(r.Source+"|"+r.Destination,r.DestinationPort.Value.ToString(),r.Id,context.TimestampUtc,3))
return NoMatch();
     var seen=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(seen==WebSignatureObservation.None)return NoMatch();
     if(seen==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1808","owner-research"),
       new DetectionEvidenceItem("matched_conditions","manage_shape","rule"),
       new DetectionEvidenceItem("outcome","management_port_probe_only","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "Public client probing SNMP, NETCONF, and HTTPS management ports observed; response, authorization and security outcome unknown",
       evidence,c=>{
         c.AddEvidence(0.43,"typed-producer-input");
         c.AddEvidence(0.35,"independent-workbook-predicate");
         c.AddCorrelation(0.12,"coherent-observation");
       },count:3,windowSeconds:300);
     
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
   
 }
}
