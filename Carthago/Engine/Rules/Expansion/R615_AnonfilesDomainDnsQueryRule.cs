// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED: R2550; xUnit authored, 0 executed.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 public sealed class R615_AnonfilesDomainDnsQueryRule : EvidenceDrivenPrecisionRuleBase
 {
  private static readonly RuleDescriptor Rule = new(
    RuleId:"R615",Name:"Anonfiles file-sharing domain DNS query",Category:"DnsAdvanced",
    Description:"Parser-backed DNS query shape only; outcome unknown.",
    DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R615.Enabled",EnabledByDefault:true);
  private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
  {
   RuleId="R615",Name="Anonfiles file-sharing domain DNS query",Category="DnsAdvanced",
   Description="Workbook R2550 DNS query signature; no authenticated outcome.",
   Severity=SeverityLevel.Medium,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
   RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Dns},
   RequiredFields=new[]{"source","destination_or_host","dns_qname","dns_qtype"},
   EvidenceFields=new[]{"dns.signature","matched_conditions","outcome"},
   PositiveConditions=new[]{
    "A bounded parser-labeled DNS query is observed with coherent endpoints.",
    "Only this rule's independent, explicit workbook signature qualifies.",
    "A client request does not establish server response, success or compromise."
   },
   NegativeConditions=new[]{
    "Reject missing or contradictory protocol fields and unrelated benign near-misses.",
    "Reject free-form Info only, duplicated packet IDs, stale time and cooldown repeats.",
    "Never infer exploitation, attribution or successful exfiltration from a request."
   },
   FalsePositives=new[]{"Legitimate authorized testing, administration, replay or historical IOC lookup."},
   MinimumConfidence=82,WindowThreshold=1,Window=TimeSpan.FromMinutes(5),
   Cooldown=TimeSpan.FromMinutes(10),DistinctBy="exact_peer_pair_and_independent_signature",
   TuningKnobs=new[]{"Mode","ApprovedScanners","ApprovedMaintenanceWindows"},
   RequiredTests=new[]{"positive and near miss","wrong method or port","missing conflicting metadata",
      "duplicate ID and cooldown","redacted evidence and registry uniqueness"}
  });
  private readonly WebSignatureCooldown _cooldown=new();
  public R615_AnonfilesDomainDnsQueryRule():base(Rule,Profile){}
  protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
  {
   var r=context.Record;
   if(!DnsSignatureRequestEvidence.TryGetQuery(r,out var qname)||!SignatureMatches(qname))return NoMatch();
   var state=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
   if(state==WebSignatureObservation.None)return NoMatch();
   if(state==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
   var items=new[]{
    new DetectionEvidenceItem("dns.signature","workbook.R2550.query","bounded-dns-parser"),
    new DetectionEvidenceItem("matched_conditions","rule_specific_dns_query_shape","rule"),
    new DetectionEvidenceItem("outcome","dns_query_only_unknown","rule")
   };
   var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
    "Specific suspicious DNS query observed; security outcome unknown",
    items, confidence=>{
      confidence.AddEvidence(0.45,"parsed-dns-query");
      confidence.AddEvidence(0.34,"workbook-specific-signature");
      confidence.AddCorrelation(0.12,"coherent-source-destination");
    },count:1,windowSeconds:300);
   DnsSignatureRequestEvidence.RedactQuery(evt,qname);
   return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
  }
  private static bool EndsIn(string name,string domain)
  =>name==domain||name.EndsWith("."+domain,StringComparison.Ordinal);
  private static bool SignatureMatches(string name){return EndsIn(name,"anonfiles.com");}
 }
}
