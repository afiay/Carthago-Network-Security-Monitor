// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed. Research R2037.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Independent R2037: Script HTTP GET with repeated double-percent-encoded segments.</summary>
 public sealed class R673_ScriptProcessRepeatedDoublePercentEncodedHttpGetRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
     RuleId:"R673",Name:"Script HTTP GET with repeated double-percent-encoded segments",Category:"HttpApi",
     Description:"Script HTTP GET with repeated double-percent-encoded segments. This is URL-encoding shape, not a proved custom encoder, malware or successful execution.",
     DefaultSeverity:SeverityLevel.Low,ConfigKey:"Rules.R673.Enabled",
     EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R673",Name="Script HTTP GET with repeated double-percent-encoded segments",Category="HttpApi",
     Description="Original workbook R2037: R019 generic encoded URI, R619 Java expressions; this requires multiple explicit double-percent markers plus attributed script process.. This is URL-encoding shape, not a proved custom encoder, malware or successful execution.",
     Severity=SeverityLevel.Low,
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
     FalsePositives=new[]{"This is URL-encoding shape, not a proved custom encoder, malware or successful execution. Legitimate tools and security testing can trigger this candidate."},
     MinimumConfidence=80,
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
   
   public R673_ScriptProcessRepeatedDoublePercentEncodedHttpGetRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)||method!="GET"
||!Research666Evidence.Outbound(r)
||!Research666Evidence.Process(r,"python.exe","pythonw.exe","powershell.exe","pwsh.exe")
||!RepeatedDoubleEncoding(uri))return NoMatch();
     var state=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(state==WebSignatureObservation.None)return NoMatch();
     if(state==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R2037","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_doubleencoded_predicate","rule"),
       new DetectionEvidenceItem("outcome","double_encoded_uri_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Low,
       "Script HTTP GET with repeated double-percent-encoded segments observed; process identity and security outcome unverified",
       evidence,c=>{
         c.AddEvidence(0.44,"coherent-typed-packet-metadata");
         c.AddEvidence(0.35,"distinct-workbook-signature");
         c.AddCorrelation(0.12,"bounded-network-context");
       },count:1,windowSeconds:120);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
   private static bool RepeatedDoubleEncoding(string uri)
{
 int count=0,start=0;
 while((start=uri.IndexOf("%25",start,StringComparison.OrdinalIgnoreCase))>=0)
 {
  count++;start+=3;if(count>=4)return true;
 }
 return false;
}
 }
}
