// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed. Workbook R1342.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
  /// <summary>Independent workbook R1342 candidate; no exploitation, outcome, or actor attribution.</summary>
  public sealed class R645_PunycodeLoginFormPostExposureRule : EvidenceDrivenPrecisionRuleBase
  {
    private static readonly RuleDescriptor Rule = new(
      RuleId:"R645",Name:"Cleartext login-form POST to a punycode HTTP host",Category:"HttpApi",
      Description:"Cleartext login-form POST to a punycode HTTP host. Observed evidence only; Cannot inspect credential contents, verify domain mimicry or infer phishing; legitimate internationalized domains and tests may match.",
      DefaultSeverity:SeverityLevel.Low,ConfigKey:"Rules.R645.Enabled",EnabledByDefault:true);
    private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
    {
      RuleId="R645",Name:"Cleartext login-form POST to a punycode HTTP host",Category="HttpApi",
      Description:"Source-only candidate from R1342: Cannot inspect credential contents, verify domain mimicry or infer phishing; legitimate internationalized domains and tests may match.",
      Severity=SeverityLevel.Low,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
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
      FalsePositives=new[]{"Cannot inspect credential contents, verify domain mimicry or infer phishing; legitimate internationalized domains and tests may match."},
      MinimumConfidence=80,WindowThreshold=1,
      Window=TimeSpan.FromMinutes(5),Cooldown=TimeSpan.FromMinutes(10),
      DistinctBy="rule_specific_typed_observation_exact_peer_or_bounded_window",
      TuningKnobs=new[]{"Mode","ApprovedAdminHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
      RequiredTests=new[]{"exact positive and benign near miss","missing/contradictory protocol or metadata",
        "duplicate IDs, expired time, cooldown","safe redacted evidence and honest scope",
        "candidate shadow policy, independent registry registration"}
    });
    private readonly WebSignatureCooldown _cooldown=new();
    public R645_PunycodeLoginFormPostExposureRule():base(Rule,Profile){}

    protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
    {
      var r=context.Record;
      if(!WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)||!Specific(r,method,uri))return NoMatch();
      var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
      if(observed==WebSignatureObservation.None)return NoMatch();
      if(observed==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
      var evidence=new[]
      {
        new DetectionEvidenceItem("research.identifier","workbook.R1342","source-research"),
        new DetectionEvidenceItem("matched_conditions","independent_phishform_predicate","rule"),
        new DetectionEvidenceItem("outcome","http_request_only_unknown","rule")
      };
      var evt=CreateDetectionEvent(context,SeverityLevel.Low,
        "Observed Cleartext login-form POST to a punycode HTTP host; no authenticated outcome established",
        evidence,confidence=>{
          confidence.AddEvidence(0.45,"bounded-observed-phishform-metadata");
          confidence.AddEvidence(0.34,"specific-workbook-shape");
          confidence.AddCorrelation(0.12,"coherent-typed-observation");
        },count:1,windowSeconds:300);
      
      return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
    }
    private static bool Specific(TrafficRecord r,string method,string uri){if(method!="POST"||r.HttpHost is not {Length:>5 and <254} host||r.HttpRequestHeaders is not {Length:>10 and <4096} hdr)return false;var path=uri.Split('?')[0].ToLowerInvariant();if(path is not ("/login" or "/signin" or "/authenticate" or "/wp-login.php" or "/session"))return false;var labels=host.Split('.');if(!labels.Any(l=>l.StartsWith("xn--",StringComparison.OrdinalIgnoreCase)))return false;return hdr.Contains("Content-Type: application/x-www-form-urlencoded",StringComparison.OrdinalIgnoreCase)||hdr.Contains("Content-Type: multipart/form-data",StringComparison.OrdinalIgnoreCase);}
  }
}
