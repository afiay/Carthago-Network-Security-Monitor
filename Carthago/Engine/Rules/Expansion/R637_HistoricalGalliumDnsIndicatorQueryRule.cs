// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed. Workbook R2385.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
  /// <summary>Independent workbook R2385 candidate; no exploitation, outcome, or actor attribution.</summary>
  public sealed class R637_HistoricalGalliumDnsIndicatorQueryRule : EvidenceDrivenPrecisionRuleBase
  {
    private static readonly RuleDescriptor Rule = new(
      RuleId:"R637",Name:"Historical GALLIUM-associated DNS indicator query",Category:"DnsAdvanced",
      Description:"Historical GALLIUM-associated DNS indicator query. Observed evidence only; Historical 2019 research, stale domains and possible reuse; DNS query is not evidence of actor attribution.",
      DefaultSeverity:SeverityLevel.Low,ConfigKey:"Rules.R637.Enabled",EnabledByDefault:true);
    private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
    {
      RuleId="R637",Name:"Historical GALLIUM-associated DNS indicator query",Category="DnsAdvanced",
      Description:"Source-only candidate from R2385: Historical 2019 research, stale domains and possible reuse; DNS query is not evidence of actor attribution.",
      Severity=SeverityLevel.Low,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
      RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Dns},
      RequiredFields=new[]{"source","destination_or_host","protocol_or_port","dns_qname","dns_qtype"},
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
      FalsePositives=new[]{"Historical 2019 research, stale domains and possible reuse; DNS query is not evidence of actor attribution."},
      MinimumConfidence=78,WindowThreshold=1,
      Window=TimeSpan.FromMinutes(5),Cooldown=TimeSpan.FromMinutes(10),
      DistinctBy="rule_specific_typed_observation_exact_peer_or_bounded_window",
      TuningKnobs=new[]{"Mode","ApprovedAdminHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
      RequiredTests=new[]{"exact positive and benign near miss","missing/contradictory protocol or metadata",
        "duplicate IDs, expired time, cooldown","safe redacted evidence and honest scope",
        "candidate shadow policy, independent registry registration"}
    });
    private readonly WebSignatureCooldown _cooldown=new();
    public R637_HistoricalGalliumDnsIndicatorQueryRule():base(Rule,Profile){}

    protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
    {
      var r=context.Record;
      if(!DnsSignatureRequestEvidence.TryGetQuery(r,out var name)||!Specific(r,name))return NoMatch();
      var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
      if(observed==WebSignatureObservation.None)return NoMatch();
      if(observed==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
      var evidence=new[]
      {
        new DetectionEvidenceItem("research.identifier","workbook.R2385","source-research"),
        new DetectionEvidenceItem("matched_conditions","independent_dns_predicate","rule"),
        new DetectionEvidenceItem("outcome","dns_query_only_unknown","rule")
      };
      var evt=CreateDetectionEvent(context,SeverityLevel.Low,
        "Observed Historical GALLIUM-associated DNS indicator query; no authenticated outcome established",
        evidence,confidence=>{
          confidence.AddEvidence(0.45,"bounded-observed-dns-metadata");
          confidence.AddEvidence(0.34,"specific-workbook-shape");
          confidence.AddCorrelation(0.12,"coherent-typed-observation");
        },count:1,windowSeconds:300);
      DnsSignatureRequestEvidence.RedactQuery(evt,name);
      return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
    }
    private static bool Specific(TrafficRecord r,string name){return name is "asyspy256.ddns.net" or "hotkillmail9sddcc.ddns.net" or "rosaf112.ddns.net" or "cvdfhjh1231.myftp.biz" or "sz2016rose.ddns.net" or "dffwescwer4325.myftp.biz" or "cvdfhjh1231.ddns.net";}
  }
}
