// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed. Workbook R2769.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
  /// <summary>Independent workbook R2769 candidate; no exploitation, outcome, or actor attribution.</summary>
  public sealed class R642_ScriptProcessBrowserAgentHttpPostRule : EvidenceDrivenPrecisionRuleBase
  {
    private static readonly RuleDescriptor Rule = new(
      RuleId:"R642",Name:"Script interpreter HTTP POST with browser-like user agent",Category:"HttpApi",
      Description:"Script interpreter HTTP POST with browser-like user agent. Observed evidence only; No process parent lineage or API-caller provenance; a browser-like User-Agent is not proof of spoofing and the local PID may be untrusted.",
      DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R642.Enabled",EnabledByDefault:true);
    private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
    {
      RuleId="R642",Name:"Script interpreter HTTP POST with browser-like user agent",Category="HttpApi",
      Description:"Source-only candidate from R2769: No process parent lineage or API-caller provenance; a browser-like User-Agent is not proof of spoofing and the local PID may be untrusted.",
      Severity=SeverityLevel.Medium,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
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
      FalsePositives=new[]{"No process parent lineage or API-caller provenance; a browser-like User-Agent is not proof of spoofing and the local PID may be untrusted."},
      MinimumConfidence=82,WindowThreshold=1,
      Window=TimeSpan.FromMinutes(5),Cooldown=TimeSpan.FromMinutes(10),
      DistinctBy="rule_specific_typed_observation_exact_peer_or_bounded_window",
      TuningKnobs=new[]{"Mode","ApprovedAdminHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
      RequiredTests=new[]{"exact positive and benign near miss","missing/contradictory protocol or metadata",
        "duplicate IDs, expired time, cooldown","safe redacted evidence and honest scope",
        "candidate shadow policy, independent registry registration"}
    });
    private readonly WebSignatureCooldown _cooldown=new();
    public R642_ScriptProcessBrowserAgentHttpPostRule():base(Rule,Profile){}

    protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
    {
      var r=context.Record;
      if(!WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)||!Specific(r,method,uri))return NoMatch();
      var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
      if(observed==WebSignatureObservation.None)return NoMatch();
      if(observed==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
      var evidence=new[]
      {
        new DetectionEvidenceItem("research.identifier","workbook.R2769","source-research"),
        new DetectionEvidenceItem("matched_conditions","independent_httpprocess_predicate","rule"),
        new DetectionEvidenceItem("outcome","http_request_only_unknown","rule")
      };
      var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
        "Observed Script interpreter HTTP POST with browser-like user agent; no authenticated outcome established",
        evidence,confidence=>{
          confidence.AddEvidence(0.45,"bounded-observed-httpprocess-metadata");
          confidence.AddEvidence(0.34,"specific-workbook-shape");
          confidence.AddCorrelation(0.12,"coherent-typed-observation");
        },count:1,windowSeconds:300);
      
      return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
    }
    private static bool Specific(TrafficRecord r,string method,string uri){if(method!="POST"||r.ProcessId<=0||r.HttpUserAgent is not {Length:>10 and <260})return false;var p=r.ProcessName?.Trim().Replace('\\','/').Split('/').Last().ToLowerInvariant();if(p is not ("powershell.exe" or "pwsh.exe" or "wscript.exe" or "cscript.exe" or "mshta.exe"))return false;return r.HttpUserAgent.Contains("Mozilla/5.0",StringComparison.OrdinalIgnoreCase)&&(r.HttpUserAgent.Contains("Chrome/",StringComparison.OrdinalIgnoreCase)||r.HttpUserAgent.Contains("Firefox/",StringComparison.OrdinalIgnoreCase)||r.HttpUserAgent.Contains("Edg/",StringComparison.OrdinalIgnoreCase));}
  }
}
