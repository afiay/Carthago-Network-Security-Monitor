// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit authored, zero executed. Workbook R1983.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 public sealed class R682_SystemUtilityBrowserAgentHttpGetHeartbeatRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
    RuleId:"R682",Name:"Rundll32/MSHTA browser-agent HTTP heartbeat-shaped GET sequence",Category:"HttpApi",
    Description:"Rundll32/MSHTA browser-agent HTTP heartbeat-shaped GET sequence; No browser impersonation intent, HTTP response, C2 beacon or executable identity proof is established.",
    DefaultSeverity:SeverityLevel.Low,ConfigKey:"Rules.R682.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R682",Name="Rundll32/MSHTA browser-agent HTTP heartbeat-shaped GET sequence",Category="HttpApi",
     Description="Workbook R1983. R642 requires a script-host HTTP POST with browser-like UA; this requires rundll32/mshta GET heartbeat route repeated three times with cadence. No browser impersonation intent, HTTP response, C2 beacon or executable identity proof is established.",
     Severity=SeverityLevel.Low,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Http,RuleTelemetryKind.Process},
     RequiredFields=new[]{"source","destination_or_host","protocol_or_port","http.method","http.uri"},
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
     FalsePositives=new[]{"Authorized management, network inventory, diagnostics and security testing may resemble this signal. No browser impersonation intent, HTTP response, C2 beacon or executable identity proof is established."},
     MinimumConfidence=80,WindowThreshold=3,Window=TimeSpan.FromMinutes(5),
     Cooldown=TimeSpan.FromMinutes(10),DistinctBy="independent_rule_specific_ip_peer_or_bounded_window",
     TuningKnobs=new[]{"Mode","ApprovedManagementHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
     RequiredTests=new[]{"exact positive and benign near miss","wrong method/port/direction/producer",
       "source and destination correlation, out-of-order and duplicate IDs",
       "event evidence privacy, bounded state and cooldown",
       "Candidate Shadow rule identity and registry uniqueness"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   private readonly Research666TimedWindow _timed=new();
   public R682_SystemUtilityBrowserAgentHttpGetHeartbeatRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)||method!="GET"
 ||!Research676Evidence.PrivateToPublic(r)
 ||!Research676Evidence.Process(r,"rundll32.exe","mshta.exe")
 ||r.HttpUserAgent==null
 ||!r.HttpUserAgent.Contains("Mozilla/5.0",StringComparison.OrdinalIgnoreCase)
 ||!r.HttpUserAgent.Contains("Chrome/",StringComparison.OrdinalIgnoreCase)
 ||!uri.Split('?')[0].Equals("/api/v1/heartbeat",StringComparison.OrdinalIgnoreCase)
 ||r.L4Len is null or <100 or >1000)return NoMatch();
if(!_timed.Observe(r.Source+"|"+r.Destination+"|"+r.ProcessId,r.Id,r.L4Len.Value,context.TimestampUtc,3,true))
return NoMatch();
     var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(observed==WebSignatureObservation.None)return NoMatch();
     if(observed==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var items=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1983","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_poll_typed_shape","rule"),
       new DetectionEvidenceItem("outcome","browser_ua_heartbeat_request_sequence_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Low,
       "Rundll32/MSHTA browser-agent HTTP heartbeat-shaped GET sequence observed; No browser impersonation intent, HTTP response, C2 beacon or executable identity proof is established.",
       items,c=>{
         c.AddEvidence(0.43,"typed-transport-and-endpoint-fields");
         c.AddEvidence(0.34,"specific-workbook-behavior");
         c.AddCorrelation(0.12,"independent-observation-window");
       },count:3,windowSeconds:300);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
 }
}
