// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit authored, zero executed. Workbook R2789.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 public sealed class R678_SequentialInternalSubnetIcmpEchoWalkRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
    RuleId:"R678",Name:"Sequential three-host internal-subnet ICMP echo discovery",Category:"NetworkDiscovery",
    Description:"Sequential three-host internal-subnet ICMP echo discovery; No full network scan, unauthorized discovery or ARP probe is inferred.",
    DefaultSeverity:SeverityLevel.Low,ConfigKey:"Rules.R678.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R678",Name="Sequential three-host internal-subnet ICMP echo discovery",Category="NetworkDiscovery",
     Description="Workbook R2789. R643 requires EtherNet/IP ListIdentity on 44818; R670 matches fixed-destination timed ICMP echoes; this walks successive IPs. No full network scan, unauthorized discovery or ARP probe is inferred.",
     Severity=SeverityLevel.Low,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Flow},
     RequiredFields=new[]{"source","destination_or_host","protocol_or_port","icmp.type_code","destination"},
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
     FalsePositives=new[]{"Authorized management, network inventory, diagnostics and security testing may resemble this signal. No full network scan, unauthorized discovery or ARP probe is inferred."},
     MinimumConfidence=78,WindowThreshold=3,Window=TimeSpan.FromMinutes(5),
     Cooldown=TimeSpan.FromMinutes(10),DistinctBy="independent_rule_specific_ip_peer_or_bounded_window",
     TuningKnobs=new[]{"Mode","ApprovedManagementHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
     RequiredTests=new[]{"exact positive and benign near miss","wrong method/port/direction/producer",
       "source and destination correlation, out-of-order and duplicate IDs",
       "event evidence privacy, bounded state and cooldown",
       "Candidate Shadow rule identity and registry uniqueness"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   private readonly Research676OrderedWindow _ordered=new();
   public R678_SequentialInternalSubnetIcmpEchoWalkRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(r.Id==Guid.Empty||r.IpVersion!=4||r.IsTcp||r.IsUdp||r.IsQuic
 ||!string.Equals(r.Protocol,"ICMP",StringComparison.OrdinalIgnoreCase)
 ||r.IcmpTypeCode!=0x0800||r.L4Len is null or <4 or >256
 ||r.HttpMethod!=null||r.DnsQname!=null
 ||!Research676Evidence.PrivatePair(r,out var src,out var dst))return NoMatch();
var b=dst.GetAddressBytes();if(b[3]==0||b[3]==255)return NoMatch();
if(!_ordered.Observe(src+"|"+Research676Evidence.Prefix24(dst),b[3],r.Id,context.TimestampUtc,90))
 return NoMatch();
     var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(observed==WebSignatureObservation.None)return NoMatch();
     if(observed==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var items=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R2789","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_icmp_typed_shape","rule"),
       new DetectionEvidenceItem("outcome","subnet_echo_walk_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Low,
       "Sequential three-host internal-subnet ICMP echo discovery observed; No full network scan, unauthorized discovery or ARP probe is inferred.",
       items,c=>{
         c.AddEvidence(0.43,"typed-transport-and-endpoint-fields");
         c.AddEvidence(0.34,"specific-workbook-behavior");
         c.AddCorrelation(0.12,"independent-observation-window");
       },count:3,windowSeconds:300);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
 }
}
