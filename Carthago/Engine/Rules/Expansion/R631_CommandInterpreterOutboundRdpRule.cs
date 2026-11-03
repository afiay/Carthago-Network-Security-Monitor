// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, 0 executed. Research R2221.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
  /// <summary>Independent workbook R2221 predicate; observational only.</summary>
  public sealed class R631_CommandInterpreterOutboundRdpRule : EvidenceDrivenPrecisionRuleBase
  {
    private static readonly RuleDescriptor Rule=new(
      RuleId:"R631", Name:"Unusual command interpreter outbound RDP",Category:"EvasionInfra",
      Description:"Original R2221; R073 RDP lateral burst and R124 ingress exposure; this is specific unusual local process to a public RDP endpoint. Only observable packet fields, no asserted outcome.",
      DefaultSeverity:SeverityLevel.Medium,
      ConfigKey:"Rules.R631.Enabled",EnabledByDefault:true);
    private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
    {
      RuleId="R631",Name="Unusual command interpreter outbound RDP",Category:"EvasionInfra",
      Description="Narrowed source candidate from R2221. R073 RDP lateral burst and R124 ingress exposure; this is specific unusual local process to a public RDP endpoint",
      Severity=SeverityLevel.Medium,Maturity=RulePrecisionMaturity.Candidate,
      RuntimeMode=RuleRuntimeMode.Shadow,
      RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Process},
      RequiredFields=new[]{"source","destination_or_host","protocol_or_port","process.name","process.id"},
      EvidenceFields=new[]{"process.signature","matched_conditions","outcome"},
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
      FalsePositives=new[]{"Best-effort Windows PID attribution or normal management tools can resemble the behavior."},
      MinimumConfidence=82,
      WindowThreshold=1,Window=TimeSpan.FromMinutes(5),Cooldown=TimeSpan.FromMinutes(10),
      DistinctBy="exact_source_destination_and_independent_signature",
      TuningKnobs=new[]{"Mode","ApprovedAdminHosts","ApprovedScanners","ApprovedMaintenanceWindows"},
      RequiredTests=new[]{"specific positive and near-miss negative","missing and contradictory fields",
        "duplicate IDs and cooldown","privacy and honest unverified outcome",
        "Candidate Shadow mode and uniqueness"}
    });
    private readonly WebSignatureCooldown _cooldown=new();
    public R631_CommandInterpreterOutboundRdpRule():base(Rule,Profile){}
    protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
    {
      var r=context.Record;
      if(!ProcessSignatureEvidence.TryExternalTcp(r,out var p)||!SignatureMatches(r,p))return NoMatch();
      var state=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
      if(state==WebSignatureObservation.None)return NoMatch();
      if(state==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
      var evidence=new[]
      {
        new DetectionEvidenceItem("process.signature","workbook.R2221.process","bounded-record-metadata"),
        new DetectionEvidenceItem("matched_conditions","independent_process_shape","rule"),
        new DetectionEvidenceItem("outcome","process_flow_identity_unverified","rule")
      };
      var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
        "Specific process-associated TCP flow observed; no process execution or compromise inferred",evidence, confidence=>
        {
          confidence.AddEvidence(0.44,"structured-process-metadata");
          confidence.AddEvidence(0.35,"distinct-workbook-predicate");
          confidence.AddCorrelation(0.12,"coherent-source-destination");
        },count:1,windowSeconds:300);
      return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
    }
    private static bool EndsIn(string name,string domain)=>ProcessSignatureEvidence.EndsIn(name,domain);
    private static bool SignatureMatches(TrafficRecord r,string name){return r.DestinationPort==3389 && (name=="cmd.exe"||name=="powershell.exe"||name=="pwsh.exe"||name=="wscript.exe"||name=="cscript.exe"||name=="mshta.exe"||name=="rundll32.exe");}
  }
}
