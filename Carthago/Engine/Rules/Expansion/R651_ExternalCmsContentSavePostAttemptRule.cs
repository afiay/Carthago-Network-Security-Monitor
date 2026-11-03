// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed. Workbook R1284.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>External CMS content-save POST request observed; no outcome, identity or authorization inferred.</summary>
 public sealed class R651_ExternalCmsContentSavePostAttemptRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
    RuleId:"R651", Name:"External CMS content-save POST request observed",Category:"HttpApi",
    Description:"External CMS content-save POST request observed. R087 monitors webshell upload, R169 admin login; this requires an explicit content-editor save POST from public to private.",
    DefaultSeverity:SeverityLevel.Medium,
    ConfigKey:"Rules.R651.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
    RuleId="R651",Name="External CMS content-save POST request observed",Category="HttpApi",
    Description="R087 monitors webshell upload, R169 admin login; this requires an explicit content-editor save POST from public to private.",
    Severity=SeverityLevel.Medium,
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
    FalsePositives=new[]{"Authorized maintenance, vulnerability assessment, application management or ordinary named-process use may match. R087 monitors webshell upload, R169 admin login; this requires an explicit content-editor save POST from public to private."},
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
   
   public R651_ExternalCmsContentSavePostAttemptRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)||method!="POST"
  ||!Research646Evidence.Pair(r,true,out _,out _)
  ||r.HttpRequestHeaders is not {Length:>15 and <=4096} h)return NoMatch();
 var path=uri.Split('?')[0];
 if(!(path.Equals("/admin/content/save",StringComparison.OrdinalIgnoreCase)
    ||path.Equals("/admin/pages/update",StringComparison.OrdinalIgnoreCase)
    ||path.Equals("/administrator/content/save",StringComparison.OrdinalIgnoreCase)))return NoMatch();
 if(!h.Contains("Content-Type: application/x-www-form-urlencoded",StringComparison.OrdinalIgnoreCase)
  && !h.Contains("Content-Type: application/json",StringComparison.OrdinalIgnoreCase))return NoMatch();
     var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(observed==WebSignatureObservation.None)return NoMatch();
     if(observed==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1284","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_cms_shape","rule"),
       new DetectionEvidenceItem("outcome","content_save_request_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "External CMS content-save POST request observed observed; outcome and authorization unverified",
       evidence,c=>{
         c.AddEvidence(0.43,"typed-network-or-parser-evidence");
         c.AddEvidence(0.36,"independent-workbook-signature");
         c.AddCorrelation(0.12,"coherent-typed-source-and-destination");
       },count:1,windowSeconds:300);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
 }
}
