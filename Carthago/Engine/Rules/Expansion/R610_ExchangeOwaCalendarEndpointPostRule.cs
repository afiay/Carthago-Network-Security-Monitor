// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED: R3039; xUnit authored, 0 executed.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 public sealed class R610_ExchangeOwaCalendarEndpointPostRule : EvidenceDrivenPrecisionRuleBase
 {
  private static readonly RuleDescriptor Rule = new(
    RuleId:"R610",Name:"Exchange OWA calendar endpoint POST",Category:"HttpApi",
    Description:"Parser-backed HTTP request shape only; outcome unknown.",
    DefaultSeverity:SeverityLevel.High,ConfigKey:"Rules.R610.Enabled",EnabledByDefault:true);
  private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
  {
   RuleId="R610",Name="Exchange OWA calendar endpoint POST",Category="HttpApi",
   Description="Workbook R3039 HTTP request signature; no authenticated outcome.",
   Severity=SeverityLevel.High,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
   RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Http},
   RequiredFields=new[]{"source","destination_or_host","http.method","http.uri"},
   EvidenceFields=new[]{"http.signature","http.method","matched_conditions","outcome"},
   PositiveConditions=new[]{
    "A bounded parser-labeled cleartext HTTP request is observed with coherent endpoints.",
    "Only this rule's independent, explicit workbook signature qualifies.",
    "A client request does not establish server response, success or compromise."
   },
   NegativeConditions=new[]{
    "Reject missing or contradictory protocol fields and unrelated benign near-misses.",
    "Reject free-form Info only, duplicated packet IDs, stale time and cooldown repeats.",
    "Never infer exploitation, attribution or successful exfiltration from a request."
   },
   FalsePositives=new[]{"Legitimate authorized testing, administration, replay or historical IOC lookup."},
   MinimumConfidence=84,WindowThreshold=1,Window=TimeSpan.FromMinutes(5),
   Cooldown=TimeSpan.FromMinutes(10),DistinctBy="exact_peer_pair_and_independent_signature",
   TuningKnobs=new[]{"Mode","ApprovedScanners","ApprovedMaintenanceWindows"},
   RequiredTests=new[]{"positive and near miss","wrong method or port","missing conflicting metadata",
      "duplicate ID and cooldown","redacted evidence and registry uniqueness"}
  });
  private readonly WebSignatureCooldown _cooldown=new();
  public R610_ExchangeOwaCalendarEndpointPostRule():base(Rule,Profile){}
  protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
  {
   var r=context.Record;
   if(!WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)
      || !SignatureMatches(method,uri,r.HttpUserAgent,r.HttpRequestHeaders))return NoMatch();
   var state=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
   if(state==WebSignatureObservation.None)return NoMatch();
   if(state==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
   var items=new[]{
    new DetectionEvidenceItem("http.signature","workbook.R3039.request","bounded-http-parser"),
    new DetectionEvidenceItem("matched_conditions","rule_specific_http_request_shape","rule"),
    new DetectionEvidenceItem("outcome","request_only_unknown","rule")
   };
   var evt=CreateDetectionEvent(context,SeverityLevel.High,
    "Specific suspicious HTTP request observed; security outcome unknown",
    items, confidence=>{
      confidence.AddEvidence(0.45,"parsed-http-request");
      confidence.AddEvidence(0.34,"workbook-specific-signature");
      confidence.AddCorrelation(0.12,"coherent-source-destination");
    },count:1,windowSeconds:300);
   return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
  }
  private static bool SignatureMatches(string method,string uri,string? ua,string? headers)
  {if(method!="POST")return false;var n=uri.IndexOf('?');var path=n<0?uri:uri.Substring(0,n);return path.Equals("/owa/calendar/a",StringComparison.OrdinalIgnoreCase)||path.StartsWith("/owa/calendar/a/",StringComparison.OrdinalIgnoreCase);}
 }
}
