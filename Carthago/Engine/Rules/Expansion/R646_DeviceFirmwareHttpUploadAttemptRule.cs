// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed. Workbook R1358.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>HTTP firmware upload request to device management endpoint; no outcome, identity or authorization inferred.</summary>
 public sealed class R646_DeviceFirmwareHttpUploadAttemptRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
    RuleId:"R646", Name:"HTTP firmware upload request to device management endpoint",Category:"HttpApi",
    Description:"HTTP firmware upload request to device management endpoint. R236 detects firmware GET/download; this requires a POST with upload path and binary content-type. No change outcome.",
    DefaultSeverity:SeverityLevel.High,
    ConfigKey:"Rules.R646.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
    RuleId="R646",Name="HTTP firmware upload request to device management endpoint",Category="HttpApi",
    Description="R236 detects firmware GET/download; this requires a POST with upload path and binary content-type. No change outcome.",
    Severity=SeverityLevel.High,
    Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
    RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Http},
    RequiredFields=new[]{"source","destination_or_host","protocol_or_port","http.method","http.uri"},
    EvidenceFields=new[]{"research.identifier","matched_conditions","outcome"},
    PositiveConditions=new[]
    {
     "Require coherent parsed protocol/tuple and exact rule-specific packet or flow signature.",
     "Independent candidate requires distinct classification and applicable network boundary.",
     "Only an observed request or flow indication is established; authorization and outcome are unknown."
    },
    NegativeConditions=new[]
    {
     "Reject port-only assertions when an L7 parser field is required; reject missing, contradictory or malformed fields.",
     "Reject benign variants, duplicate IDs, stale windows and repeated matches during cooldown.",
     "No compromise, accepted command, authenticated service, or completed transfer is inferred."
    },
    FalsePositives=new[]{"Authorized maintenance, vulnerability assessment, application management or ordinary named-process use may match. R236 detects firmware GET/download; this requires a POST with upload path and binary content-type. No change outcome."},
    MinimumConfidence=84,
    WindowThreshold=1,Window=TimeSpan.FromMinutes(5),
    Cooldown=TimeSpan.FromMinutes(10),
    DistinctBy="independent_rule_specific_source_and_destination_or_subnet",
    TuningKnobs=new[]{"Mode","ApprovedAdminHosts","ApprovedScanners","ApprovedMaintenanceWindows"},
    RequiredTests=new[]{"exact positive and benign near miss","missing or contradictory transport and parser fields",
    "unique IDs, out-of-order observations, expiry and cooldown","redacted evidence, no outcome inference",
    "registry uniqueness and Candidate Shadow policy"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   
   public R646_DeviceFirmwareHttpUploadAttemptRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!WebSignatureRequestEvidence.TryGet(r,out var method,out var uri) ||method!="POST"
 ||!Research646Evidence.Pair(r,false,out _,out _)
 ||r.HttpRequestHeaders is not {Length:>15 and <=4096} h)return NoMatch();
 var path=uri.Split('?')[0];
 if(!(path.EndsWith("/firmware/upload",StringComparison.OrdinalIgnoreCase)
   ||path.EndsWith("/api/firmware",StringComparison.OrdinalIgnoreCase)
   ||path.EndsWith("/firmware/upgrade",StringComparison.OrdinalIgnoreCase)))return NoMatch();
 if(!(h.Contains("Content-Type: application/octet-stream",StringComparison.OrdinalIgnoreCase)
  ||h.Contains("Content-Type: multipart/form-data",StringComparison.OrdinalIgnoreCase)))return NoMatch();
     var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(observed==WebSignatureObservation.None)return NoMatch();
     if(observed==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1358","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_firmware_shape","rule"),
       new DetectionEvidenceItem("outcome","firmware_request_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.High,
       "HTTP firmware upload request to device management endpoint observed; outcome and authorization unverified",
       evidence,c=>{
         c.AddEvidence(0.43,"typed-network-or-parser-evidence");
         c.AddEvidence(0.36,"independent-workbook-signature");
         c.AddCorrelation(0.12,"coherent-typed-source-and-destination");
       },count:1,windowSeconds:300);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
 }
}
