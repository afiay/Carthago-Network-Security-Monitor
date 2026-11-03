// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit authored, zero executed. Workbook R2040.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 public sealed class R680_UnusualProcessInternalPrivateHostFanoutRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
    RuleId:"R680",Name:"Unusual local process SYN fanout to three internal hosts",Category:"EvasionInfra",
    Description:"Unusual local process SYN fanout to three internal hosts; PID enrichment is best-effort, and an internal SYN fanout is not proof of proxying or lateral command execution.",
    DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R680.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R680",Name="Unusual local process SYN fanout to three internal hosts",Category="EvasionInfra",
     Description="Workbook R2040. R650 Curl/Wget fanout requires public /24s; R674 is public-client inbound followed by external outbound; this is three private peer hosts. PID enrichment is best-effort, and an internal SYN fanout is not proof of proxying or lateral command execution.",
     Severity=SeverityLevel.Medium,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Process},
     RequiredFields=new[]{"source","destination_or_host","protocol_or_port","process.name","process.id","tcp.flags"},
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
     FalsePositives=new[]{"Authorized management, network inventory, diagnostics and security testing may resemble this signal. PID enrichment is best-effort, and an internal SYN fanout is not proof of proxying or lateral command execution."},
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
   public R680_UnusualProcessInternalPrivateHostFanoutRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!Research676Evidence.Syn(r)||!Research676Evidence.PrivatePair(r,out var src,out var dst)
 ||r.DestinationPort is null or <1024 or >65535
 ||r.DestinationPort is 3389 or 445 or 5985 or 5986
 ||!Research676Evidence.Process(r,"rundll32.exe","mshta.exe","regsvr32.exe"))return NoMatch();
var b=dst.GetAddressBytes();if(b[3]==0||b[3]==255)return NoMatch();
if(!_distinct.Observe(r.Source+"|"+Research676Evidence.Prefix24(dst)+"|"+r.ProcessId,
dst.ToString(),r.Id,context.TimestampUtc,3))return NoMatch();
     var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(observed==WebSignatureObservation.None)return NoMatch();
     if(observed==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var items=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R2040","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_internal_typed_shape","rule"),
       new DetectionEvidenceItem("outcome","local_process_internal_syn_fanout_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "Unusual local process SYN fanout to three internal hosts observed; PID enrichment is best-effort, and an internal SYN fanout is not proof of proxying or lateral command execution.",
       items,c=>{
         c.AddEvidence(0.43,"typed-transport-and-endpoint-fields");
         c.AddEvidence(0.34,"specific-workbook-behavior");
         c.AddCorrelation(0.12,"independent-observation-window");
       },count:3,windowSeconds:300);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
 }
}
