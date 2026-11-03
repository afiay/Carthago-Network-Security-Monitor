// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit authored, zero executed. Workbook R2019.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 public sealed class R681_UnusualProcessDualPublicProxyPortSynRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
    RuleId:"R681",Name:"Unusual local process contacts two public peers on proxy-associated TCP ports",Category:"EvasionTunnel",
    Description:"Unusual local process contacts two public peers on proxy-associated TCP ports; No SOCKS handshake, established proxy, C2 relay or forwarded payload is observed.",
    DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R681.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R681",Name="Unusual local process contacts two public peers on proxy-associated TCP ports",Category="EvasionTunnel",
     Description="Workbook R2019. R263 may cover a single proxy-process egress; this requires two distinct public peers on 1080/3128/8080/8888 within five minutes. No SOCKS handshake, established proxy, C2 relay or forwarded payload is observed.",
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
     FalsePositives=new[]{"Authorized management, network inventory, diagnostics and security testing may resemble this signal. No SOCKS handshake, established proxy, C2 relay or forwarded payload is observed."},
     MinimumConfidence=82,WindowThreshold=2,Window=TimeSpan.FromMinutes(5),
     Cooldown=TimeSpan.FromMinutes(10),DistinctBy="independent_rule_specific_ip_peer_or_bounded_window",
     TuningKnobs=new[]{"Mode","ApprovedManagementHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
     RequiredTests=new[]{"exact positive and benign near miss","wrong method/port/direction/producer",
       "source and destination correlation, out-of-order and duplicate IDs",
       "event evidence privacy, bounded state and cooldown",
       "Candidate Shadow rule identity and registry uniqueness"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   private readonly Research656DistinctWindow _distinct=new();
   public R681_UnusualProcessDualPublicProxyPortSynRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!Research676Evidence.Syn(r)||!Research676Evidence.PrivateToPublic(r)
 ||r.DestinationPort is not (1080 or 3128 or 8080 or 8888)
 ||!Research676Evidence.Process(r,"rundll32.exe","mshta.exe","wscript.exe","cscript.exe"))
return NoMatch();
if(!_distinct.Observe(r.Source+"|"+r.ProcessId+"|"+NetworkBatch266270Evidence.Process(r),
r.Destination!,r.Id,context.TimestampUtc,2))return NoMatch();
     var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(observed==WebSignatureObservation.None)return NoMatch();
     if(observed==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var items=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R2019","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_external_typed_shape","rule"),
       new DetectionEvidenceItem("outcome","local_process_proxy_port_dual_peer_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "Unusual local process contacts two public peers on proxy-associated TCP ports observed; No SOCKS handshake, established proxy, C2 relay or forwarded payload is observed.",
       items,c=>{
         c.AddEvidence(0.43,"typed-transport-and-endpoint-fields");
         c.AddEvidence(0.34,"specific-workbook-behavior");
         c.AddCorrelation(0.12,"independent-observation-window");
       },count:2,windowSeconds:300);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
 }
}
