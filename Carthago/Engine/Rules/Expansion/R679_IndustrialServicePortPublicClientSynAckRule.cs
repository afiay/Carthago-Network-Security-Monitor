// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit authored, zero executed. Workbook R2782.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 public sealed class R679_IndustrialServicePortPublicClientSynAckRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
    RuleId:"R679",Name:"Private OT-service listener TCP SYN-ACK to public client",Category:"IotOtAdvanced",
    Description:"Private OT-service listener TCP SYN-ACK to public client; Port-associated SYN-ACK alone does not verify an ICS device, protocol decoder success, successful authentication or NAT exposure.",
    DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R679.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R679",Name="Private OT-service listener TCP SYN-ACK to public client",Category="IotOtAdvanced",
     Description="Workbook R2782. R644/R648/R649 cover RDP/VNC/WinRM listener response; this requires one of 102/502/44818 OT service ports. Port-associated SYN-ACK alone does not verify an ICS device, protocol decoder success, successful authentication or NAT exposure.",
     Severity=SeverityLevel.Medium,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow},
     RequiredFields=new[]{"source","destination_or_host","protocol_or_port","tcp.flags","source.port","destination.port"},
     EvidenceFields=new[]{"research.identifier","matched_conditions","outcome"},
     PositiveConditions=new[]{
       "Require coherent typed transport/parser observations and this independent rule predicate.",
       "If a sequence is required, use a bounded per-instance window of unique packet IDs.",
       "Events describe observed request/response/flow shape, not authenticated security outcomes."
     },
     NegativeConditions=new[]{
       "Reject missing or contradictory producer fields and out-of-scope ports/directions.",
       "Reject similar-but-benign near misses, packet ID replays, stale/out-of-order time and cooldown repeats.",
       "Do not infer a device identity, command execution, approved exposure, C2 tunnel or credential compromise."
     },
     FalsePositives=new[]{"Authorized management, network inventory, diagnostics and security testing may resemble this signal. Port-associated SYN-ACK alone does not verify an ICS device, protocol decoder success, successful authentication or NAT exposure."},
     MinimumConfidence=82,WindowThreshold=1,Window=TimeSpan.FromMinutes(5),
     Cooldown=TimeSpan.FromMinutes(10),DistinctBy="independent_rule_specific_ip_peer_or_bounded_window",
     TuningKnobs=new[]{"Mode","ApprovedManagementHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
     RequiredTests=new[]{"exact positive and benign near miss","wrong method/port/direction/producer",
       "source and destination correlation, out-of-order and duplicate IDs",
       "event evidence privacy, bounded state and cooldown",
       "Candidate Shadow rule identity and registry uniqueness"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   
   public R679_IndustrialServicePortPublicClientSynAckRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!Research676Evidence.SynAck(r)||!Research676Evidence.PrivateToPublic(r)
 ||r.SourcePort is not (102 or 502 or 44818))return NoMatch();
     var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(observed==WebSignatureObservation.None)return NoMatch();
     if(observed==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var items=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R2782","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_icsack_typed_shape","rule"),
       new DetectionEvidenceItem("outcome","ot_service_port_syn_ack_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "Private OT-service listener TCP SYN-ACK to public client observed; Port-associated SYN-ACK alone does not verify an ICS device, protocol decoder success, successful authentication or NAT exposure.",
       items,c=>{
         c.AddEvidence(0.43,"typed-transport-and-endpoint-fields");
         c.AddEvidence(0.34,"specific-workbook-behavior");
         c.AddCorrelation(0.12,"independent-observation-window");
       },count:1,windowSeconds:300);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
 }
}
