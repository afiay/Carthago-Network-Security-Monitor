// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed. Research R2932.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Independent R2932: Specific SQL injection token in cleartext HTTP GET URI.</summary>
 public sealed class R666_SpecificSqlInjectionGetUriRequestRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
     RuleId:"R666",Name:"Specific SQL injection token in cleartext HTTP GET URI",Category:"HttpApi",
     Description:"Specific SQL injection token in cleartext HTTP GET URI. Only observed URI bytes, no database execution, returned data, or HTTP status.",
     DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R666.Enabled",
     EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R666",Name="Specific SQL injection token in cleartext HTTP GET URI",Category="HttpApi",
     Description="Original workbook R2932: R085 detects broader SQLi; this requires one of a restricted set of concrete query tokens in a parser-labeled GET.. Only observed URI bytes, no database execution, returned data, or HTTP status.",
     Severity=SeverityLevel.Medium,
     Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Http},
     RequiredFields=new[]{"source","destination_or_host","protocol_or_port","http.method","http.uri"},
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
     FalsePositives=new[]{"Only observed URI bytes, no database execution, returned data, or HTTP status. Legitimate tools and security testing can trigger this candidate."},
     MinimumConfidence=82,
     WindowThreshold=1,
     Window=TimeSpan.FromMinutes(2),Cooldown=TimeSpan.FromMinutes(10),
     DistinctBy="source_peer_and_independent_signature_or_sequence",
     TuningKnobs=new[]{"Mode","ApprovedProcesses","ApprovedMaintenanceWindows","ApprovedDestinations"},
     RequiredTests=new[]{"positive typed sample and benign negative","missing producer and contradictory fields",
       "independent thresholds, duplicate/out-of-order/expiration and cooldown",
       "redacted evidence/no sensitive payload or asserted security outcome",
       "Candidate Shadow mode and registry uniqueness"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   
   public R666_SpecificSqlInjectionGetUriRequestRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)
||method!="GET"||!Research666Evidence.Outbound(r)||!SqlShape(uri))return NoMatch();
     var state=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(state==WebSignatureObservation.None)return NoMatch();
     if(state==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R2932","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_sql_predicate","rule"),
       new DetectionEvidenceItem("outcome","http_sqli_request_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "Specific SQL injection token in cleartext HTTP GET URI observed; process identity and security outcome unverified",
       evidence,c=>{
         c.AddEvidence(0.44,"coherent-typed-packet-metadata");
         c.AddEvidence(0.35,"distinct-workbook-signature");
         c.AddCorrelation(0.12,"bounded-network-context");
       },count:1,windowSeconds:120);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
   private static bool SqlShape(string uri)
{
 var question=uri.IndexOf('?');if(question<=0)return false;
 var query=uri.Substring(question+1);
 return query.Contains("UNION%20SELECT",StringComparison.OrdinalIgnoreCase)
  ||query.Contains("UNION+SELECT",StringComparison.OrdinalIgnoreCase)
  ||query.Contains("information_schema.tables",StringComparison.OrdinalIgnoreCase)
  ||query.Contains("%27%20OR%201%3D1",StringComparison.OrdinalIgnoreCase)
  ||query.Contains("SELECT%28SLEEP%2810%29",StringComparison.OrdinalIgnoreCase);
}
 }
}
