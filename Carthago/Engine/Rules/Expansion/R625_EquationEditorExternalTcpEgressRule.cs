// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, 0 executed. Original workbook ID R2979.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
  /// <summary>Independent locally resolved process and external TCP flow detection; no outcome attribution.</summary>
  public sealed class R625_EquationEditorExternalTcpEgressRule : EvidenceDrivenPrecisionRuleBase
  {
    private static readonly RuleDescriptor Rule=new(
      RuleId:"R625",Name:"Equation Editor Process External TCP Egress",Category:"EvasionInfra",
      Description:"locally resolved process and external TCP flow: specific workbook candidate, detection only; Process identity is best-effort and no signed executable path or malicious payload is established.",
      DefaultSeverity:SeverityLevel.High,ConfigKey:"Rules.R625.Enabled",EnabledByDefault:true);
    private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
    {
      RuleId="R625",Name="Equation Editor Process External TCP Egress",Category="EvasionInfra",
      Description="locally resolved process and external TCP flow observed only; Process identity is best-effort and no signed executable path or malicious payload is established.",
      Severity=SeverityLevel.High,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
      RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Process},
      RequiredFields=new[]{"source","destination_or_host","process.name","process.id","protocol_or_port"},
      EvidenceFields=new[]{"matched_conditions","outcome","process.category"},
      PositiveConditions=new[]
      {
        "locally resolved process and external TCP flow requires concrete structured record fields, exact match, non-ambiguous endpoints.",
        "Match only the independent workbook-derived signature; no generic text or broad family proxy.",
        "Source-only request, query, or flow evidence does not establish compromise, execution or response."
      },
      NegativeConditions=new[]
      {
        "Reject missing producer fields, contradictory transport evidence, missing endpoints and malformed inputs.",
        "Reject benign near misses, duplicate packets, stale timestamps and cooldown repeats.",
        "Never infer server outcome, authenticated process ownership or successful exploitation."
      },
      FalsePositives=new[]{"Process resolution can be stale, incomplete, or involve legitimate software."},
      MinimumConfidence=82,
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
    public R625_EquationEditorExternalTcpEgressRule():base(Rule,Profile){}
    protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
    {
      var r=context.Record;
      if(!NetworkBatch266270Evidence.ProcessEgress(r,out var process)||process!="eqnedt32.exe")return NoMatch();
      var result=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
      if(result==WebSignatureObservation.None)return NoMatch();
      if(result==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
      var evidence=new[]
      {
        new DetectionEvidenceItem("process.category","eqnedt32.exe","resolved-process-basename"),
        new DetectionEvidenceItem("matched_conditions","specific_process_predicate","rule"),
        new DetectionEvidenceItem("outcome","process_flow_identity_unverified","rule")
      };
      var evt=CreateDetectionEvent(context,SeverityLevel.High,
        "Unusual named process observed on an external TCP flow; process ownership and compromise unverified",evidence,confidence=>
        {
          confidence.AddEvidence(0.43,"typed-process-evidence");
          confidence.AddEvidence(0.35,"independent-workbook-signature");
          confidence.AddCorrelation(0.12,"coherent-source-destination");
        },count:1,windowSeconds:300);
      return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
    }
    
  }
}
