// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, 0 executed. Original workbook ID R2941.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
  /// <summary>Independent DNS query detection; no outcome attribution.</summary>
  public sealed class R620_LocaltoNetServiceDnsQueryRule : EvidenceDrivenPrecisionRuleBase
  {
    private static readonly RuleDescriptor Rule=new(
      RuleId:"R620",Name:"LocaltoNet Service DNS Query",Category:"DnsAdvanced",
      Description:"DNS query: specific workbook candidate, detection only; Sigma originally requires an initiated process connection. This narrower DNS-only variant cannot attribute a process or an established tunnel.",
      DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R620.Enabled",EnabledByDefault:true);
    private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
    {
      RuleId="R620",Name="LocaltoNet Service DNS Query",Category="DnsAdvanced",
      Description="DNS query observed only; Sigma originally requires an initiated process connection. This narrower DNS-only variant cannot attribute a process or an established tunnel.",
      Severity=SeverityLevel.Medium,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
      RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Dns},
      RequiredFields=new[]{"source","destination_or_host","dns_qname","dns_qtype"},
      EvidenceFields=new[]{"matched_conditions","outcome","dns.signature"},
      PositiveConditions=new[]
      {
        "DNS query requires concrete structured record fields, exact match, non-ambiguous endpoints.",
        "Match only the independent workbook-derived signature; no generic text or broad family proxy.",
        "Source-only request, query, or flow evidence does not establish compromise, execution or response."
      },
      NegativeConditions=new[]
      {
        "Reject missing producer fields, contradictory transport evidence, missing endpoints and malformed inputs.",
        "Reject benign near misses, duplicate packets, stale timestamps and cooldown repeats.",
        "Never infer server outcome, authenticated process ownership or successful exploitation."
      },
      FalsePositives=new[]{"Authorized testing, benign administration or historical indicator lookups can match."},
      MinimumConfidence=80,
      WindowThreshold=1,Window=TimeSpan.FromMinutes(5),Cooldown=TimeSpan.FromMinutes(10),
      DistinctBy="exact_peer_pair_and_rule_specific_signature",
      TuningKnobs=new[]{"Mode","ApprovedMaintenanceWindows","ApprovedScanners"},
      RequiredTests=new[]
      {
        "exact positive and near-miss negative",
        "missing and conflicting transport or producer fields",
        "duplicate packet IDs, stale timestamps and cooldown",
        "redacted outcome-only evidence and registry uniqueness",
        "untrusted import and unverified outcome boundary"
      }
    });
    private readonly WebSignatureCooldown _cooldown=new();
    public R620_LocaltoNetServiceDnsQueryRule():base(Rule,Profile){}
    protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
    {
      var r=context.Record;
      if(!DnsSignatureRequestEvidence.TryGetQuery(r,out var name)||!SignatureMatches(name))return NoMatch();
      var result=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
      if(result==WebSignatureObservation.None)return NoMatch();
      if(result==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
      var evidence=new[]
      {
        new DetectionEvidenceItem("dns.signature","workbook.R2941.dns_shape","parsed-record"),
        new DetectionEvidenceItem("matched_conditions","specific_dns_predicate","rule"),
        new DetectionEvidenceItem("outcome","dns_query_only_unknown","rule")
      };
      var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
        "Suspicious domain DNS query observed; no process or callback outcome established",evidence,confidence=>
        {
          confidence.AddEvidence(0.43,"typed-dns-evidence");
          confidence.AddEvidence(0.35,"independent-workbook-signature");
          confidence.AddCorrelation(0.12,"coherent-source-destination");
        },count:1,windowSeconds:300);
      DnsSignatureRequestEvidence.RedactQuery(evt,name);
   return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
    }
    private static bool EndsIn(string name,string suffix)=>name==suffix||name.EndsWith("."+suffix,StringComparison.Ordinal);private static bool SignatureMatches(string name){return EndsIn(name,"localto.net")||EndsIn(name,"localtonet.com");}
  }
}
