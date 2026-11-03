// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit authored, zero executed. Workbook R1137.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 public sealed class R676_UnicastBroadcastNetworkAddressSynKnockRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
    RuleId:"R676",Name:"Unicast–broadcast–network-address TCP SYN signaling sequence",Category:"NetworkDiscovery",
    Description:"Unicast–broadcast–network-address TCP SYN signaling sequence; No firewall activation, router change, magic packet acceptance or SSH session is observed.",
    DefaultSeverity:SeverityLevel.Low,ConfigKey:"Rules.R676.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R676",Name="Unicast–broadcast–network-address TCP SYN signaling sequence",Category="NetworkDiscovery",
     Description="Workbook R1137. Existing sweeps and R585 multi-service probes; requires one TCP port and an ordered unicast, .255 broadcast, .0 subnet-address sequence. No firewall activation, router change, magic packet acceptance or SSH session is observed.",
     Severity=SeverityLevel.Low,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
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
     FalsePositives=new[]{"Authorized management, network inventory, diagnostics and security testing may resemble this signal. No firewall activation, router change, magic packet acceptance or SSH session is observed."},
     MinimumConfidence=80,WindowThreshold=3,Window=TimeSpan.FromMinutes(5),
     Cooldown=TimeSpan.FromMinutes(10),DistinctBy="independent_rule_specific_ip_peer_or_bounded_window",
     TuningKnobs=new[]{"Mode","ApprovedManagementHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
     RequiredTests=new[]{"exact positive and benign near miss","wrong method/port/direction/producer",
       "source and destination correlation, out-of-order and duplicate IDs",
       "event evidence privacy, bounded state and cooldown",
       "Candidate Shadow rule identity and registry uniqueness"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   private readonly Research676KnockWindow _knocks=new();
   public R676_UnicastBroadcastNetworkAddressSynKnockRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!Research676Evidence.Syn(r)||!Research676Evidence.PrivatePair(r,out var src,out var dst)
 ||r.DestinationPort is not (22 or 23 or 443))return NoMatch();
var b=dst.GetAddressBytes();var stage=b[3]==255?1:b[3]==0?2:0;
if(!_knocks.Observe(src+"|"+Research676Evidence.Prefix24(dst)+"|"+r.DestinationPort,stage,r.Id,context.TimestampUtc))
 return NoMatch();
     var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(observed==WebSignatureObservation.None)return NoMatch();
     if(observed==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var items=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1137","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_knock_typed_shape","rule"),
       new DetectionEvidenceItem("outcome","ordered_knock_shaped_tcp_syn_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Low,
       "Unicast–broadcast–network-address TCP SYN signaling sequence observed; No firewall activation, router change, magic packet acceptance or SSH session is observed.",
       items,c=>{
         c.AddEvidence(0.43,"typed-transport-and-endpoint-fields");
         c.AddEvidence(0.34,"specific-workbook-behavior");
         c.AddCorrelation(0.12,"independent-observation-window");
       },count:3,windowSeconds:300);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
 }
}
