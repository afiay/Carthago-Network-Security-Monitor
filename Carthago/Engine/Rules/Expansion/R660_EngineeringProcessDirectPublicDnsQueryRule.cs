// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, 0 executed. Workbook R2731.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Independent OT engineering process sends native DNS query directly to public resolver; no success, identity or exfiltration inference.</summary>
 public sealed class R660_EngineeringProcessDirectPublicDnsQueryRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
     RuleId:"R660",Name:"OT engineering process sends native DNS query directly to public resolver",Category:"DnsAdvanced",
     Description:"OT engineering process sends native DNS query directly to public resolver. R102 is DNS label tunneling; this rule requires attributed engineering process and a public resolver, without claiming DNS policy violation.",
     DefaultSeverity:SeverityLevel.Low,
     ConfigKey:"Rules.R660.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R660",Name="OT engineering process sends native DNS query directly to public resolver",Category="DnsAdvanced",Description="R102 is DNS label tunneling; this rule requires attributed engineering process and a public resolver, without claiming DNS policy violation.",
     Severity=SeverityLevel.Low,
     Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Dns,RuleTelemetryKind.Process},
     RequiredFields=new[]{"source","destination_or_host","dns_qname","dns_qtype","process.id"},
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
     FalsePositives=new[]{"Authorized developer workflows, management clients, automated scripts or normal network operations may match. R102 is DNS label tunneling; this rule requires attributed engineering process and a public resolver, without claiming DNS policy violation."},
     MinimumConfidence=80,
     WindowThreshold=1,
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
   
   public R660_EngineeringProcessDirectPublicDnsQueryRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!DnsSignatureRequestEvidence.TryGetQuery(r,out var qname)
||!Research656Evidence.ValidProcess(r,"tia.exe","plcsim.exe","codesyscontrol.exe","hmi.exe")
||!Research656Evidence.PrivatePublic(r,true)
||r.Destination is not ("8.8.8.8" or "8.8.4.4" or "1.1.1.1" or "1.0.0.1" or "9.9.9.9"))
return NoMatch();
     var seen=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(seen==WebSignatureObservation.None)return NoMatch();
     if(seen==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R2731","owner-research"),
       new DetectionEvidenceItem("matched_conditions","otdns_shape","rule"),
       new DetectionEvidenceItem("outcome","dns_query_process_identity_unverified","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Low,
       "OT engineering process sends native DNS query directly to public resolver observed; response, authorization and security outcome unknown",
       evidence,c=>{
         c.AddEvidence(0.43,"typed-producer-input");
         c.AddEvidence(0.35,"independent-workbook-predicate");
         c.AddCorrelation(0.12,"coherent-observation");
       },count:1,windowSeconds:300);
     DnsSignatureRequestEvidence.RedactQuery(evt,qname);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
   
 }
}
