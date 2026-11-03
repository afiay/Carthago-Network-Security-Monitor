// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed. Research R1993.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Independent R1993: Same local PID receives public TCP SYN then initiates external high-port SYN.</summary>
 public sealed class R674_SameProcessInboundToOutboundPublicTcpSynSequenceRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
     RuleId:"R674",Name:"Same local PID receives public TCP SYN then initiates external high-port SYN",Category:"EvasionTunnel",
     Description:"Same local PID receives public TCP SYN then initiates external high-port SYN. Two SYNs do not prove process spawning, packet forwarding, NAT, an established proxy or a C2 relay.",
     DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R674.Enabled",
     EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R674",Name="Same local PID receives public TCP SYN then initiates external high-port SYN",Category="EvasionTunnel",
     Description="Original workbook R1993: R263 user-space proxy egress covers an individual flow; this is ordered two-direction network behavior from same local address and attributed process.. Two SYNs do not prove process spawning, packet forwarding, NAT, an established proxy or a C2 relay.",
     Severity=SeverityLevel.Medium,
     Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Process},
     RequiredFields=new[]{"source","destination_or_host","protocol_or_port","process.id","tcp.flags_or_payload"},
     EvidenceFields=new[]{"research.identifier","matched_conditions","outcome"},
     PositiveConditions=new[]{
       "The packet/flow must have coherent typed producer metadata and a specific independent rule predicate.",
       "Every process attribution is best-effort local tuple correlation, not an authenticated process event.",
       "Only request, handshake, packet, or flow observation is established, never security outcome."
     },
     NegativeConditions=new[]{
       "No port-only or Info-only proxy for a required packet parser field.",
       "Reject missing/contradictory transport fields, unrelated benign near-misses and forged source context.",
       "Reject duplicate IDs, out-of-order observations and cooldown repeats; never infer compromise."
     },
     FalsePositives=new[]{"Two SYNs do not prove process spawning, packet forwarding, NAT, an established proxy or a C2 relay. Legitimate tools and security testing can trigger this candidate."},
     MinimumConfidence=82,
     WindowThreshold=2,
     Window=TimeSpan.FromMinutes(2),Cooldown=TimeSpan.FromMinutes(10),
     DistinctBy="source_peer_and_independent_signature_or_sequence",
     TuningKnobs=new[]{"Mode","ApprovedProcesses","ApprovedMaintenanceWindows","ApprovedDestinations"},
     RequiredTests=new[]{"positive typed sample and benign negative","missing producer and contradictory fields",
       "independent thresholds, duplicate/out-of-order/expiration and cooldown",
       "redacted evidence/no sensitive payload or asserted security outcome",
       "Candidate Shadow mode and registry uniqueness"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   private readonly Research666BridgeWindow _bridge=new();
   public R674_SameProcessInboundToOutboundPublicTcpSynSequenceRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!Research666Evidence.Tcp(r)||r.TcpFlags!=0x02||r.L4Len is not (null or 0)
||r.HttpMethod!=null||r.DnsQname!=null||r.TlsVersion!=null
||!Research666Evidence.Process(r,"powershell.exe","pwsh.exe","rundll32.exe","netsh.exe"))
return NoMatch();
var inbound=Research666Evidence.Inbound(r)&&r.DestinationPort is >1024 and <=65535;
var outbound=Research666Evidence.Outbound(r)&&r.DestinationPort is >1024 and <=65535;
if(!inbound&&!outbound)return NoMatch();
var local=inbound?r.Destination:r.Source;
var pid=NetworkBatch266270Evidence.Process(r);
if(!_bridge.Observe(local+"|"+r.ProcessId+"|"+pid,r.Id,context.TimestampUtc,inbound))
return NoMatch();
     var state=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(state==WebSignatureObservation.None)return NoMatch();
     if(state==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1993","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_bridge_predicate","rule"),
       new DetectionEvidenceItem("outcome","inbound_outbound_syn_sequence_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "Same local PID receives public TCP SYN then initiates external high-port SYN observed; process identity and security outcome unverified",
       evidence,c=>{
         c.AddEvidence(0.44,"coherent-typed-packet-metadata");
         c.AddEvidence(0.35,"distinct-workbook-signature");
         c.AddCorrelation(0.12,"bounded-network-context");
       },count:2,windowSeconds:120);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
   
 }
}
