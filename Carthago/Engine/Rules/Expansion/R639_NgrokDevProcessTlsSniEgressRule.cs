// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed. Workbook R2146.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
  /// <summary>Independent workbook R2146 candidate; no exploitation, outcome, or actor attribution.</summary>
  public sealed class R639_NgrokDevProcessTlsSniEgressRule : EvidenceDrivenPrecisionRuleBase
  {
    private static readonly RuleDescriptor Rule = new(
      RuleId:"R639",Name:"Local process TLS SNI contact to ngrok developer-domain variants",Category:"EvasionInfra",
      Description:"Local process TLS SNI contact to ngrok developer-domain variants. Observed evidence only; TLS SNI alone does not establish an initiated connection, use of a tunnel or payload transfer; approved ngrok deployments are common.",
      DefaultSeverity:SeverityLevel.Low,ConfigKey:"Rules.R639.Enabled",EnabledByDefault:true);
    private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
    {
      RuleId="R639",Name="Local process TLS SNI contact to ngrok developer-domain variants",Category="EvasionInfra",
      Description="Source-only candidate from R2146: TLS SNI alone does not establish an initiated connection, use of a tunnel or payload transfer; approved ngrok deployments are common.",
      Severity=SeverityLevel.Low,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
      RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Process},
      RequiredFields=new[]{"source","destination_or_host","protocol_or_port","process.name","process.id"},
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
      FalsePositives=new[]{"TLS SNI alone does not establish an initiated connection, use of a tunnel or payload transfer; approved ngrok deployments are common."},
      MinimumConfidence=82,WindowThreshold=1,
      Window=TimeSpan.FromMinutes(5),Cooldown=TimeSpan.FromMinutes(10),
      DistinctBy="rule_specific_typed_observation_exact_peer_or_bounded_window",
      TuningKnobs=new[]{"Mode","ApprovedAdminHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
      RequiredTests=new[]{"exact positive and benign near miss","missing/contradictory protocol or metadata",
        "duplicate IDs, expired time, cooldown","safe redacted evidence and honest scope",
        "candidate shadow policy, independent registry registration"}
    });
    private readonly WebSignatureCooldown _cooldown=new();
    public R639_NgrokDevProcessTlsSniEgressRule():base(Rule,Profile){}

    protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
    {
      var r=context.Record;
      if(!ProcessSignatureEvidence.TryExternalTcp(r,out var name)||!Specific(r,name))return NoMatch();
      var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
      if(observed==WebSignatureObservation.None)return NoMatch();
      if(observed==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
      var evidence=new[]
      {
        new DetectionEvidenceItem("research.identifier","workbook.R2146","source-research"),
        new DetectionEvidenceItem("matched_conditions","independent_process_predicate","rule"),
        new DetectionEvidenceItem("outcome","process_flow_identity_unverified","rule")
      };
      var evt=CreateDetectionEvent(context,SeverityLevel.Low,
        "Observed Local process TLS SNI contact to ngrok developer-domain variants; no authenticated outcome established",
        evidence,confidence=>{
          confidence.AddEvidence(0.45,"bounded-observed-process-metadata");
          confidence.AddEvidence(0.34,"specific-workbook-shape");
          confidence.AddCorrelation(0.12,"coherent-typed-observation");
        },count:1,windowSeconds:300);
      
      return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
    }
    private static bool EndsIn(string? value,string domain){if(string.IsNullOrWhiteSpace(value))return false;return ProcessSignatureEvidence.EndsIn(value.TrimEnd('.'),domain);}
private static bool Specific(TrafficRecord r,string name){return r.TlsVersion!=null && r.HttpMethod==null && (EndsIn(r.Sni,"ngrok-free.dev") || EndsIn(r.Sni,"ngrok.dev"));}
  }
}
