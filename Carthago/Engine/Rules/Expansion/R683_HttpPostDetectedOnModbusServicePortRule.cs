// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit authored, zero executed. Workbook R2777.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 public sealed class R683_HttpPostDetectedOnModbusServicePortRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
    RuleId:"R683",Name:"Parsed cleartext HTTP POST on native Modbus TCP service port",Category:"IotOtAdvanced",
    Description:"Parsed cleartext HTTP POST on native Modbus TCP service port; A legitimate nonstandard HTTP service may use port 502; no ICS protocol masquerade intent or exploit is proved.",
    DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R683.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R683",Name="Parsed cleartext HTTP POST on native Modbus TCP service port",Category="IotOtAdvanced",
     Description="Workbook R2777. R653 requires parsed Modbus non-write requests; this explicitly requires HTTP parser evidence instead of Modbus on TCP/502. A legitimate nonstandard HTTP service may use port 502; no ICS protocol masquerade intent or exploit is proved.",
     Severity=SeverityLevel.Medium,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Http},
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
     FalsePositives=new[]{"Authorized management, network inventory, diagnostics and security testing may resemble this signal. A legitimate nonstandard HTTP service may use port 502; no ICS protocol masquerade intent or exploit is proved."},
     MinimumConfidence=82,WindowThreshold=1,Window=TimeSpan.FromMinutes(5),
     Cooldown=TimeSpan.FromMinutes(10),DistinctBy="independent_rule_specific_ip_peer_or_bounded_window",
     TuningKnobs=new[]{"Mode","ApprovedManagementHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
     RequiredTests=new[]{"exact positive and benign near miss","wrong method/port/direction/producer",
       "source and destination correlation, out-of-order and duplicate IDs",
       "event evidence privacy, bounded state and cooldown",
       "Candidate Shadow rule identity and registry uniqueness"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   
   public R683_HttpPostDetectedOnModbusServicePortRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)
 ||method!="POST"||r.DestinationPort!=502||r.TlsVersion!=null
 ||r.ApplicationProtocol!="HTTP"
 ||!uri.StartsWith("/api/",StringComparison.OrdinalIgnoreCase)
 ||!Research676Evidence.PublicToPrivate(r)&&!Research676Evidence.PrivatePair(r,out _,out _)
   &&!Research676Evidence.PrivateToPublic(r))
return NoMatch();
     var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(observed==WebSignatureObservation.None)return NoMatch();
     if(observed==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var items=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R2777","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_mismatch_typed_shape","rule"),
       new DetectionEvidenceItem("outcome","http_over_modbus_port_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "Parsed cleartext HTTP POST on native Modbus TCP service port observed; A legitimate nonstandard HTTP service may use port 502; no ICS protocol masquerade intent or exploit is proved.",
       items,c=>{
         c.AddEvidence(0.43,"typed-transport-and-endpoint-fields");
         c.AddEvidence(0.34,"specific-workbook-behavior");
         c.AddCorrelation(0.12,"independent-observation-window");
       },count:1,windowSeconds:300);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
 }
}
