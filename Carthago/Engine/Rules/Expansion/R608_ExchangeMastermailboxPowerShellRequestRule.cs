// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED: R2273; xUnit authored, 0 executed.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 public sealed class R608_ExchangeMastermailboxPowerShellRequestRule : EvidenceDrivenPrecisionRuleBase
 {
  private static readonly RuleDescriptor Rule = new(
    RuleId:"R608",Name:"Exchange mastermailbox PowerShell SSRF request",Category:"HttpApi",
    Description:"Parser-backed HTTP request shape only; outcome unknown.",
    DefaultSeverity:SeverityLevel.High,ConfigKey:"Rules.R608.Enabled",EnabledByDefault:true);
  private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
  {
   RuleId="R608",Name="Exchange mastermailbox PowerShell SSRF request",Category="HttpApi",
   Description="Workbook R2273 HTTP request signature; no authenticated outcome.",
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
  public R608_ExchangeMastermailboxPowerShellRequestRule():base(Rule,Profile){}
  protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
  {
   var r=context.Record;
   if(!WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)
      || !SignatureMatches(method,uri,r.HttpUserAgent,r.HttpRequestHeaders))return NoMatch();
   var state=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
   if(state==WebSignatureObservation.None)return NoMatch();
   if(state==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
   var items=new[]{
    new DetectionEvidenceItem("http.signature","workbook.R2273.request","bounded-http-parser"),
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
  {return method=="POST" && uri.Contains("/owa/mastermailbox",StringComparison.OrdinalIgnoreCase)&&uri.Contains("/powershell",StringComparison.OrdinalIgnoreCase)&&(ua?.Contains("Chrome/105.0.5195.54",StringComparison.OrdinalIgnoreCase)??false);}
 }
}
