// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed. Workbook R2012.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
  /// <summary>Independent workbook R2012 candidate; no exploitation, outcome, or actor attribution.</summary>
  public sealed class R641_OfficeProcessHighEntropyDnsQueryRule : EvidenceDrivenPrecisionRuleBase
  {
    private static readonly RuleDescriptor Rule = new(
      RuleId:"R641",Name:"Office process-associated high-entropy DNS query",Category:"DnsAdvanced",
      Description:"Office process-associated high-entropy DNS query. Observed evidence only; Best-effort process association and domain entropy cannot establish a DGA or process execution; Office telemetry may be absent.",
      DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R641.Enabled",EnabledByDefault:true);
    private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
    {
      RuleId="R641",Name:"Office process-associated high-entropy DNS query",Category="DnsAdvanced",
      Description:"Source-only candidate from R2012: Best-effort process association and domain entropy cannot establish a DGA or process execution; Office telemetry may be absent.",
      Severity=SeverityLevel.Medium,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
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
      FalsePositives=new[]{"Best-effort process association and domain entropy cannot establish a DGA or process execution; Office telemetry may be absent."},
      MinimumConfidence=82,WindowThreshold=1,
      Window=TimeSpan.FromMinutes(5),Cooldown=TimeSpan.FromMinutes(10),
      DistinctBy="rule_specific_typed_observation_exact_peer_or_bounded_window",
      TuningKnobs=new[]{"Mode","ApprovedAdminHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
      RequiredTests=new[]{"exact positive and benign near miss","missing/contradictory protocol or metadata",
        "duplicate IDs, expired time, cooldown","safe redacted evidence and honest scope",
        "candidate shadow policy, independent registry registration"}
    });
    private readonly WebSignatureCooldown _cooldown=new();
    public R641_OfficeProcessHighEntropyDnsQueryRule():base(Rule,Profile){}

    protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
    {
      var r=context.Record;
      if(!DnsSignatureRequestEvidence.TryGetQuery(r,out var name)||!Specific(r,name))return NoMatch();
      var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
      if(observed==WebSignatureObservation.None)return NoMatch();
      if(observed==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
      var evidence=new[]
      {
        new DetectionEvidenceItem("research.identifier","workbook.R2012","source-research"),
        new DetectionEvidenceItem("matched_conditions","independent_dnsprocess_predicate","rule"),
        new DetectionEvidenceItem("outcome","dns_process_identity_unverified","rule")
      };
      var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
        "Observed Office process-associated high-entropy DNS query; no authenticated outcome established",
        evidence,confidence=>{
          confidence.AddEvidence(0.45,"bounded-observed-dnsprocess-metadata");
          confidence.AddEvidence(0.34,"specific-workbook-shape");
          confidence.AddCorrelation(0.12,"coherent-typed-observation");
        },count:1,windowSeconds:300);
      DnsSignatureRequestEvidence.RedactQuery(evt,name);
      return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
    }
    private static bool Specific(TrafficRecord r,string name){if(!ProcessName(r.ProcessName,out var n)||r.ProcessId<=0||n is not ("winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe"))return false;var first=name.Split('.')[0];if(first.Length<24||first.Length>63||first.Count(char.IsDigit)<5||first.Distinct().Count()<13)return false;return !name.EndsWith(".microsoft.com",StringComparison.Ordinal)&&!name.EndsWith(".office.com",StringComparison.Ordinal)&&!name.EndsWith(".outlook.com",StringComparison.Ordinal)&&!name.EndsWith(".windows.net",StringComparison.Ordinal);}private static bool ProcessName(string? value,out string name){name=string.Empty;if(string.IsNullOrWhiteSpace(value)||value.Length>260)return false;var last=value.Trim().Replace('\\','/');name=last.Substring(last.LastIndexOf('/')+1).ToLowerInvariant();return name.Length is >=4 and <=64;}
  }
}
