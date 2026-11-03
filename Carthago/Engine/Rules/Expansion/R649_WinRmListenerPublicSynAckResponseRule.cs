// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed. Workbook R1372.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>WinRM private listener SYN-ACK response to a public client; no outcome, identity or authorization inferred.</summary>
 public sealed class R649_WinRmListenerPublicSynAckResponseRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
    RuleId:"R649", Name:"WinRM private listener SYN-ACK response to a public client",Category:"IdentityAccess",
    Description:"WinRM private listener SYN-ACK response to a public client. R125 flags inbound WinRM service access, not observed server SYN-ACK; this requires response direction and flags.",
    DefaultSeverity:SeverityLevel.Medium,
    ConfigKey:"Rules.R649.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
    RuleId="R649",Name="WinRM private listener SYN-ACK response to a public client",Category="IdentityAccess",
    Description="R125 flags inbound WinRM service access, not observed server SYN-ACK; this requires response direction and flags.",
    Severity=SeverityLevel.Medium,
    Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
    RequiredTelemetry=new[]{RuleTelemetryKind.Flow},
    RequiredFields=new[]{"source","destination_or_host","protocol_or_port","tcp.flags","source.port"},
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
    FalsePositives=new[]{"Authorized maintenance, vulnerability assessment, application management or ordinary named-process use may match. R125 flags inbound WinRM service access, not observed server SYN-ACK; this requires response direction and flags."},
    MinimumConfidence=82,
    WindowThreshold=1,Window=TimeSpan.FromMinutes(5),
    Cooldown=TimeSpan.FromMinutes(10),
    DistinctBy="independent_rule_specific_source_and_destination_or_subnet",
    TuningKnobs=new[]{"Mode","ApprovedAdminHosts","ApprovedScanners","ApprovedMaintenanceWindows"},
    RequiredTests=new[]{"exact positive and benign near miss","missing or contradictory transport and parser fields",
    "unique IDs, out-of-order observations, expiry and cooldown","redacted evidence, no outcome inference",
    "registry uniqueness and Candidate Shadow policy"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   
   public R649_WinRmListenerPublicSynAckResponseRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!Research646Evidence.SynAck(r,5985) && !Research646Evidence.SynAck(r,5986))return NoMatch();
     var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(observed==WebSignatureObservation.None)return NoMatch();
     if(observed==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1372","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_synack_winrm_shape","rule"),
       new DetectionEvidenceItem("outcome","winrm_tcp_syn_ack_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "WinRM private listener SYN-ACK response to a public client observed; outcome and authorization unverified",
       evidence,c=>{
         c.AddEvidence(0.43,"typed-network-or-parser-evidence");
         c.AddEvidence(0.36,"independent-workbook-signature");
         c.AddCorrelation(0.12,"coherent-typed-source-and-destination");
       },count:1,windowSeconds:300);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
 }
}
