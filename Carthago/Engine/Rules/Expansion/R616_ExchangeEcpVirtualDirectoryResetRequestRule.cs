// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, 0 executed. Original workbook ID R2269.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
  /// <summary>Independent HTTP request detection; no outcome attribution.</summary>
  public sealed class R616_ExchangeEcpVirtualDirectoryResetRequestRule : EvidenceDrivenPrecisionRuleBase
  {
    private static readonly RuleDescriptor Rule=new(
      RuleId:"R616",Name:"Exchange ECP Virtual Directory Reset Request",Category:"HttpApi",
      Description:"HTTP request: specific workbook candidate, detection only; The Sigma source requires HTTP 200 and machine-account username ending $, neither is established by the packet record.",
      DefaultSeverity:SeverityLevel.High,ConfigKey:"Rules.R616.Enabled",EnabledByDefault:true);
    private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
    {
      RuleId="R616",Name="Exchange ECP Virtual Directory Reset Request",Category="HttpApi",
      Description="HTTP request observed only; The Sigma source requires HTTP 200 and machine-account username ending $, neither is established by the packet record.",
      Severity=SeverityLevel.High,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
      RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Http},
      RequiredFields=new[]{"source","destination_or_host","http.method","http.uri"},
      EvidenceFields=new[]{"matched_conditions","outcome","http.signature"},
      PositiveConditions=new[]
      {
        "HTTP request requires concrete structured record fields, exact match, non-ambiguous endpoints.",
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
      MinimumConfidence=84,
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
    public R616_ExchangeEcpVirtualDirectoryResetRequestRule():base(Rule,Profile){}
    protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
    {
      var r=context.Record;
      if(!WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)||!SignatureMatches(method,uri))return NoMatch();
      var result=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
      if(result==WebSignatureObservation.None)return NoMatch();
      if(result==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
      var evidence=new[]
      {
        new DetectionEvidenceItem("http.signature","workbook.R2269.http_shape","parsed-record"),
        new DetectionEvidenceItem("matched_conditions","specific_http_predicate","rule"),
        new DetectionEvidenceItem("outcome","request_only_unknown","rule")
      };
      var evt=CreateDetectionEvent(context,SeverityLevel.High,
        "Suspicious HTTP request shape observed; response and exploitation outcome unknown",evidence,confidence=>
        {
          confidence.AddEvidence(0.43,"typed-http-evidence");
          confidence.AddEvidence(0.35,"independent-workbook-signature");
          confidence.AddCorrelation(0.12,"coherent-source-destination");
        },count:1,windowSeconds:300);
      return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
    }
    private static bool SignatureMatches(string method,string uri){if(method!="POST")return false;var ix=uri.IndexOf('?');if(ix<0||!uri.Substring(0,ix).Equals("/ecp/DDI/DDIService.svc/SetObject",StringComparison.OrdinalIgnoreCase))return false;var query=uri.Substring(ix+1);return query.Contains("schema=Reset",StringComparison.OrdinalIgnoreCase)&&query.Contains("VirtualDirectory",StringComparison.OrdinalIgnoreCase);}
  }
}
