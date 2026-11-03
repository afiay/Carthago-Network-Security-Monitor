// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit authored, zero executed. Workbook R2780.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 public sealed class R684_OpcUaPublicClientSynSynAckExchangeRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
    RuleId:"R684",Name:"Public OPC UA-port SYN and private-server SYN-ACK exchange",Category:"IotOtAdvanced",
    Description:"Public OPC UA-port SYN and private-server SYN-ACK exchange; The TCP exchange does not prove OPC UA payload, API execution, user approval, login or completed TCP handshake.",
    DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R684.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R684",Name="Public OPC UA-port SYN and private-server SYN-ACK exchange",Category="IotOtAdvanced",
     Description="Workbook R2780. R679 observes an OT-port SYN-ACK on 102/502/44818; R684 requires both directions and OPC UA port 4840. The TCP exchange does not prove OPC UA payload, API execution, user approval, login or completed TCP handshake.",
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
     FalsePositives=new[]{"Authorized management, network inventory, diagnostics and security testing may resemble this signal. The TCP exchange does not prove OPC UA payload, API execution, user approval, login or completed TCP handshake."},
     MinimumConfidence=82,WindowThreshold=2,Window=TimeSpan.FromMinutes(5),
     Cooldown=TimeSpan.FromMinutes(10),DistinctBy="independent_rule_specific_ip_peer_or_bounded_window",
     TuningKnobs=new[]{"Mode","ApprovedManagementHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
     RequiredTests=new[]{"exact positive and benign near miss","wrong method/port/direction/producer",
       "source and destination correlation, out-of-order and duplicate IDs",
       "event evidence privacy, bounded state and cooldown",
       "Candidate Shadow rule identity and registry uniqueness"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   private readonly Research676TcpSynPair _pair=new();
   public R684_OpcUaPublicClientSynSynAckExchangeRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!Research676Evidence.Tcp(r)||r.L4Len is not (null or 0)
 ||r.ApplicationProtocol!=null||r.HttpMethod!=null||r.DnsQname!=null||r.TlsVersion!=null)return NoMatch();
var request=r.DestinationPort==4840&&r.TcpFlags==0x02&&Research676Evidence.PublicToPrivate(r);
var response=r.SourcePort==4840&&r.TcpFlags==0x12&&Research676Evidence.PrivateToPublic(r);
if(!request&&!response)return NoMatch();
var pub=request?r.Source:r.Destination;
var device=request?r.Destination:r.Source;
var clientPort=request?r.SourcePort:r.DestinationPort;
if(!_pair.Observe(pub+"|"+device+"|"+clientPort,r.Id,context.TimestampUtc,request))
return NoMatch();
     var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(observed==WebSignatureObservation.None)return NoMatch();
     if(observed==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var items=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R2780","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_opc_typed_shape","rule"),
       new DetectionEvidenceItem("outcome","opcua_port_tcp_syn_synack_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "Public OPC UA-port SYN and private-server SYN-ACK exchange observed; The TCP exchange does not prove OPC UA payload, API execution, user approval, login or completed TCP handshake.",
       items,c=>{
         c.AddEvidence(0.43,"typed-transport-and-endpoint-fields");
         c.AddEvidence(0.34,"specific-workbook-behavior");
         c.AddCorrelation(0.12,"independent-observation-window");
       },count:2,windowSeconds:300);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
 }
}
