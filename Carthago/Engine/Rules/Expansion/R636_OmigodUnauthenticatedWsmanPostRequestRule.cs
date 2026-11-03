// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed. Workbook R3013.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
  /// <summary>Independent workbook R3013 candidate; no exploitation, outcome, or actor attribution.</summary>
  public sealed class R636_OmigodUnauthenticatedWsmanPostRequestRule : EvidenceDrivenPrecisionRuleBase
  {
    private static readonly RuleDescriptor Rule = new(
      RuleId:"R636",Name:"OMIGOD-like unauthenticated WSMan POST attempt",Category:"HttpApi",
      Description:"OMIGOD-like unauthenticated WSMan POST attempt. Observed evidence only; HTTP 200, server command and successful exploit are unavailable; absence of an Authorization header in the capture summary is not authenticated absence.",
      DefaultSeverity:SeverityLevel.High,ConfigKey:"Rules.R636.Enabled",EnabledByDefault:true);
    private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
    {
      RuleId="R636",Name:"OMIGOD-like unauthenticated WSMan POST attempt",Category="HttpApi",
      Description:"Source-only candidate from R3013: HTTP 200, server command and successful exploit are unavailable; absence of an Authorization header in the capture summary is not authenticated absence.",
      Severity=SeverityLevel.High,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
      RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Http},
      RequiredFields=new[]{"source","destination_or_host","protocol_or_port","http.method","http.uri"},
      EvidenceFields=new[]{"matched_conditions","research.identifier","outcome"},
      PositiveConditions=new[]
      {
        "Only typed packet metadata and this rule's independent exact predicate can satisfy the candidate.",
        "Use parser-backed HTTP/DNS/OT fields or explicitly conditional process/TCP metadata, with coherent endpoints.",
        "An observed request, query, connection attempt or SYN-ACK is not an authenticated security outcome."
      },
      NegativeConditions=new[]
      {
        "Reject missing producer fields, contradictory transport, generic port-only or Info-only evidence.",
        "Reject benign near misses, packet duplicates, stale time and cooldown repeats.",
        "Never claim successful exploitation, credential disclosure, actor attribution or established tunnel."
      },
      FalsePositives=new[]{"HTTP 200, server command and successful exploit are unavailable; absence of an Authorization header in the capture summary is not authenticated absence."},
      MinimumConfidence=84,WindowThreshold=1,
      Window=TimeSpan.FromMinutes(5),Cooldown=TimeSpan.FromMinutes(10),
      DistinctBy="rule_specific_typed_observation_exact_peer_or_bounded_window",
      TuningKnobs=new[]{"Mode","ApprovedAdminHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
      RequiredTests=new[]{"exact positive and benign near miss","missing/contradictory protocol or metadata",
        "duplicate IDs, expired time, cooldown","safe redacted evidence and honest scope",
        "candidate shadow policy, independent registry registration"}
    });
    private readonly WebSignatureCooldown _cooldown=new();
    public R636_OmigodUnauthenticatedWsmanPostRequestRule():base(Rule,Profile){}

    protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
    {
      var r=context.Record;
      if(!WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)||!Specific(r,method,uri))return NoMatch();
      var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
      if(observed==WebSignatureObservation.None)return NoMatch();
      if(observed==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
      var evidence=new[]
      {
        new DetectionEvidenceItem("research.identifier","workbook.R3013","source-research"),
        new DetectionEvidenceItem("matched_conditions","independent_http_predicate","rule"),
        new DetectionEvidenceItem("outcome","http_request_only_unknown","rule")
      };
      var evt=CreateDetectionEvent(context,SeverityLevel.High,
        "Observed OMIGOD-like unauthenticated WSMan POST attempt; no authenticated outcome established",
        evidence,confidence=>{
          confidence.AddEvidence(0.45,"bounded-observed-http-metadata");
          confidence.AddEvidence(0.34,"specific-workbook-shape");
          confidence.AddCorrelation(0.12,"coherent-typed-observation");
        },count:1,windowSeconds:300);
      
      return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
    }
    private static bool Specific(TrafficRecord r,string method,string uri){return method=="POST"&&uri.Equals("/wsman",StringComparison.OrdinalIgnoreCase)&&r.HttpRequestHeaders is {Length:>0 and <4096} h && !h.Contains("Authorization:",StringComparison.OrdinalIgnoreCase) && PositiveLength(h);}private static bool PositiveLength(string headers){foreach(var line in headers.Split('\n')){var part=line.Trim().TrimEnd('\r');if(part.StartsWith("Content-Length:",StringComparison.OrdinalIgnoreCase)&&int.TryParse(part.Substring(15).Trim(),out var n)&&n>0&&n<=4096)return true;}return false;}
  }
}
