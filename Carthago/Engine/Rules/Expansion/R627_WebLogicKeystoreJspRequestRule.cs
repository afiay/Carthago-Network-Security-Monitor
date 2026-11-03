// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, 0 executed. Research R2286.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
  /// <summary>Independent workbook R2286 predicate; observational only.</summary>
  public sealed class R627_WebLogicKeystoreJspRequestRule : EvidenceDrivenPrecisionRuleBase
  {
    private static readonly RuleDescriptor Rule=new(
      RuleId:"R627", Name:"WebLogic keystore webshell-like URI request",Category:"HttpApi",
      Description:"Original R2286; R087 webshell upload; here direct WebLogic keystore path request without upload inference. Only observable packet fields, no asserted outcome.",
      DefaultSeverity:SeverityLevel.High,
      ConfigKey:"Rules.R627.Enabled",EnabledByDefault:true);
    private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
    {
      RuleId="R627",Name="WebLogic keystore webshell-like URI request",Category="HttpApi",
      Description="Narrowed source candidate from R2286. R087 webshell upload; here direct WebLogic keystore path request without upload inference",
      Severity=SeverityLevel.High,Maturity=RulePrecisionMaturity.Candidate,
      RuntimeMode=RuleRuntimeMode.Shadow,
      RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Http},
      RequiredFields=new[]{"source","destination_or_host","protocol_or_port","http.method","http.uri"},
      EvidenceFields=new[]{"http.signature","matched_conditions","outcome"},
      PositiveConditions=new[]
      {
        "Require real structured packet/flow fields and the independent exact candidate predicate.",
        "A matching request, DNS lookup or process-associated flow is not authenticated outcome evidence.",
        "Only a bounded metadata signature is emitted, without unredacted request content."
      },
      NegativeConditions=new[]
      {
        "Reject missing or contradictory transport, absent parser context or absent local process identity.",
        "Reject ordinary near misses, duplicate IDs, out-of-order time and cooldown repeats.",
        "No CVE exploitation, domain attribution, tunnel creation or command execution is inferred."
      },
      FalsePositives=new[]{"Security testing and benign access may generate the identical URI request."},
      MinimumConfidence=84,
      WindowThreshold=1,Window=TimeSpan.FromMinutes(5),Cooldown=TimeSpan.FromMinutes(10),
      DistinctBy="exact_source_destination_and_independent_signature",
      TuningKnobs=new[]{"Mode","ApprovedAdminHosts","ApprovedScanners","ApprovedMaintenanceWindows"},
      RequiredTests=new[]{"specific positive and near-miss negative","missing and contradictory fields",
        "duplicate IDs and cooldown","privacy and honest unverified outcome",
        "Candidate Shadow mode and uniqueness"}
    });
    private readonly WebSignatureCooldown _cooldown=new();
    public R627_WebLogicKeystoreJspRequestRule():base(Rule,Profile){}
    protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
    {
      var r=context.Record;
      if(!WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)||!SignatureMatches(method,uri))return NoMatch();
      var state=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
      if(state==WebSignatureObservation.None)return NoMatch();
      if(state==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
      var evidence=new[]
      {
        new DetectionEvidenceItem("http.signature","workbook.R2286.http","bounded-record-metadata"),
        new DetectionEvidenceItem("matched_conditions","independent_http_shape","rule"),
        new DetectionEvidenceItem("outcome","request_only_unknown","rule")
      };
      var evt=CreateDetectionEvent(context,SeverityLevel.High,
        "Specific suspicious HTTP request observed; no server response or execution inferred",evidence, confidence=>
        {
          confidence.AddEvidence(0.44,"structured-http-metadata");
          confidence.AddEvidence(0.35,"distinct-workbook-predicate");
          confidence.AddCorrelation(0.12,"coherent-source-destination");
        },count:1,windowSeconds:300);
      return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
    }
    private static bool SignatureMatches(string method,string uri){if(method!="GET"&&method!="POST")return false;var question=uri.IndexOf('?');var path=question<0?uri:uri.Substring(0,question);var prefix="/config/keystore/";var i=path.IndexOf(prefix,StringComparison.OrdinalIgnoreCase);if(i<0)return false;var tail=path.Substring(i+prefix.Length);return tail.Length>3 && tail.Contains(".js",StringComparison.OrdinalIgnoreCase);}
  }
}
