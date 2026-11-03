// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed. Workbook R1417.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Curl/Wget attributed process outbound public subnet fanout; no outcome, identity or authorization inferred.</summary>
 public sealed class R650_CurlWgetProcessPublicSubnetFanoutRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
    RuleId:"R650", Name:"Curl/Wget attributed process outbound public subnet fanout",Category:"EvasionInfra",
    Description:"Curl/Wget attributed process outbound public subnet fanout. R017 sweeps internal targets; R036 heavy upload to one target. This requires one process+PID, three public /24s.",
    DefaultSeverity:SeverityLevel.Medium,
    ConfigKey:"Rules.R650.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
    RuleId="R650",Name="Curl/Wget attributed process outbound public subnet fanout",Category="EvasionInfra",
    Description="R017 sweeps internal targets; R036 heavy upload to one target. This requires one process+PID, three public /24s.",
    Severity=SeverityLevel.Medium,
    Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
    RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Process},
    RequiredFields=new[]{"source","destination_or_host","protocol_or_port","process.name","process.id"},
    EvidenceFields=new[]{"research.identifier","matched_conditions","outcome"},
    PositiveConditions=new[]
    {
     "Require coherent parsed protocol/tuple and exact rule-specific packet or flow signature.",
     "Independent candidate requires distinct classification and applicable network boundary.",
     "Only an observed request or flow indication is established; authorization and outcome are unknown."
    },
    NegativeConditions=new[]
    {
     "Reject port-only assertions when an L7 parser field is required; reject missing, contradictory or malformed fields.",
     "Reject benign variants, duplicate IDs, stale windows and repeated matches during cooldown.",
     "No compromise, accepted command, authenticated service, or completed transfer is inferred."
    },
    FalsePositives=new[]{"Authorized maintenance, vulnerability assessment, application management or ordinary named-process use may match. R017 sweeps internal targets; R036 heavy upload to one target. This requires one process+PID, three public /24s."},
    MinimumConfidence=82,
    WindowThreshold=3,Window=TimeSpan.FromMinutes(5),
    Cooldown=TimeSpan.FromMinutes(10),
    DistinctBy="independent_rule_specific_source_and_destination_or_subnet",
    TuningKnobs=new[]{"Mode","ApprovedAdminHosts","ApprovedScanners","ApprovedMaintenanceWindows"},
    RequiredTests=new[]{"exact positive and benign near miss","missing or contradictory transport and parser fields",
    "unique IDs, out-of-order observations, expiry and cooldown","redacted evidence, no outcome inference",
    "registry uniqueness and Candidate Shadow policy"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   private readonly Research646DistinctWindow _window=new();
   public R650_CurlWgetProcessPublicSubnetFanoutRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!NetworkBatch266270Evidence.ProcessEgress(r,out var process)
  ||process is not ("curl.exe" or "wget.exe" or "curl" or "wget")
  ||r.HttpMethod!=null ||r.DnsQname!=null ||r.IpVersion!=4
  ||!Research646Evidence.Pair(r,false,out _,out var destination)
  ||!_window.Observe(r.Source+"|"+r.ProcessId+"|"+process,
    Research646Evidence.Subnet24(destination),r.Id,context.TimestampUtc))return NoMatch();
     var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(observed==WebSignatureObservation.None)return NoMatch();
     if(observed==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1417","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_process_fanout_shape","rule"),
       new DetectionEvidenceItem("outcome","attributed_process_public_fanout_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "Curl/Wget attributed process outbound public subnet fanout observed; outcome and authorization unverified",
       evidence,c=>{
         c.AddEvidence(0.43,"typed-network-or-parser-evidence");
         c.AddEvidence(0.36,"independent-workbook-signature");
         c.AddCorrelation(0.12,"coherent-typed-source-and-destination");
       },count:3,windowSeconds:300);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
 }
}
