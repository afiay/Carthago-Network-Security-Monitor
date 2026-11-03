// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit authored, zero executed. Workbook R2758.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 public sealed class R685_MultiDeviceLargeS7CommResponseFanInRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
    RuleId:"R685",Name:"Large parsed S7Comm response records from three private devices",Category:"IotOtAdvanced",
    Description:"Large parsed S7Comm response records from three private devices; Large response records do not establish directory listing, point/tag identification, device inventory or compromise.",
    DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R685.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R685",Name="Large parsed S7Comm response records from three private devices",Category="IotOtAdvanced",
     Description="Workbook R2758. R654 requires public-client S7 requests to three hosts; this requires internal-client large S7Comm response fan-in, not request scanning. Large response records do not establish directory listing, point/tag identification, device inventory or compromise.",
     Severity=SeverityLevel.Medium,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.OtIcsProtocol},
     RequiredFields=new[]{"source","destination_or_host","protocol_or_port","ot.protocol","l4.length"},
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
     FalsePositives=new[]{"Authorized management, network inventory, diagnostics and security testing may resemble this signal. Large response records do not establish directory listing, point/tag identification, device inventory or compromise."},
     MinimumConfidence=82,WindowThreshold=3,Window=TimeSpan.FromMinutes(5),
     Cooldown=TimeSpan.FromMinutes(10),DistinctBy="independent_rule_specific_ip_peer_or_bounded_window",
     TuningKnobs=new[]{"Mode","ApprovedManagementHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
     RequiredTests=new[]{"exact positive and benign near miss","wrong method/port/direction/producer",
       "source and destination correlation, out-of-order and duplicate IDs",
       "event evidence privacy, bounded state and cooldown",
       "Candidate Shadow rule identity and registry uniqueness"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   private readonly Research656DistinctWindow _distinct=new();
   public R685_MultiDeviceLargeS7CommResponseFanInRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!Research676Evidence.Tcp(r)||r.SourcePort!=102
 ||r.L4Len is null or <512 or >4096||r.DnsQname!=null||r.HttpMethod!=null||r.TlsVersion!=null
 ||!string.Equals(r.ApplicationProtocol,"s7comm",StringComparison.Ordinal)
 ||!Research676Evidence.PrivatePair(r,out var device,out var client))return NoMatch();
var db=device.GetAddressBytes();if(db[3]==0||db[3]==255)return NoMatch();
if(!_distinct.Observe(client+"|"+Research676Evidence.Prefix24(device),
device.ToString(),r.Id,context.TimestampUtc,3))return NoMatch();
     var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(observed==WebSignatureObservation.None)return NoMatch();
     if(observed==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var items=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R2758","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_s7_typed_shape","rule"),
       new DetectionEvidenceItem("outcome","large_s7comm_response_fanin_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "Large parsed S7Comm response records from three private devices observed; Large response records do not establish directory listing, point/tag identification, device inventory or compromise.",
       items,c=>{
         c.AddEvidence(0.43,"typed-transport-and-endpoint-fields");
         c.AddEvidence(0.34,"specific-workbook-behavior");
         c.AddCorrelation(0.12,"independent-observation-window");
       },count:3,windowSeconds:300);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
 }
}
