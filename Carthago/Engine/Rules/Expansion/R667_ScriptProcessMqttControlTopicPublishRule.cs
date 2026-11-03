// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed. Research R1955.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Independent R1955: Script process publishes MQTT control-topic request to external broker.</summary>
 public sealed class R667_ScriptProcessMqttControlTopicPublishRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
     RuleId:"R667",Name:"Script process publishes MQTT control-topic request to external broker",Category:"EvasionTunnel",
     Description:"Script process publishes MQTT control-topic request to external broker. MQTT parser labels a publish request; no client identity, broker acceptance, C2 or actuation outcome is established.",
     DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R667.Enabled",
     EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R667",Name="Script process publishes MQTT control-topic request to external broker",Category="EvasionTunnel",
     Description="Original workbook R1955: R229 monitors retained-topic abuse and R115 frequency; this requires non-retained control-topic publish plus unusual attributed script process.. MQTT parser labels a publish request; no client identity, broker acceptance, C2 or actuation outcome is established.",
     Severity=SeverityLevel.Medium,
     Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Payload,RuleTelemetryKind.Process},
     RequiredFields=new[]{"source","destination_or_host","protocol_or_port","mqtt.publish","process.id"},
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
     FalsePositives=new[]{"MQTT parser labels a publish request; no client identity, broker acceptance, C2 or actuation outcome is established. Legitimate tools and security testing can trigger this candidate."},
     MinimumConfidence=82,
     WindowThreshold=1,
     Window=TimeSpan.FromMinutes(2),Cooldown=TimeSpan.FromMinutes(10),
     DistinctBy="source_peer_and_independent_signature_or_sequence",
     TuningKnobs=new[]{"Mode","ApprovedProcesses","ApprovedMaintenanceWindows","ApprovedDestinations"},
     RequiredTests=new[]{"positive typed sample and benign negative","missing producer and contradictory fields",
       "independent thresholds, duplicate/out-of-order/expiration and cooldown",
       "redacted evidence/no sensitive payload or asserted security outcome",
       "Candidate Shadow mode and registry uniqueness"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   
   public R667_ScriptProcessMqttControlTopicPublishRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!Research666Evidence.Outbound(r)||!Research666Evidence.Tcp(r)
||r.DestinationPort!=1883||r.HttpMethod!=null||r.DnsQname!=null||r.TlsVersion!=null
||!string.Equals(r.ApplicationProtocol,"mqtt.publish",StringComparison.Ordinal)
||!r.MqttPublishTopicObserved||!r.MqttControlTopicObserved||r.MqttRetain!=false
||!Research666Evidence.Process(r,"powershell.exe","pwsh.exe","python.exe","rundll32.exe"))
return NoMatch();
     var state=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(state==WebSignatureObservation.None)return NoMatch();
     if(state==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1955","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_mqtt_predicate","rule"),
       new DetectionEvidenceItem("outcome","mqtt_control_publish_request_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "Script process publishes MQTT control-topic request to external broker observed; process identity and security outcome unverified",
       evidence,c=>{
         c.AddEvidence(0.44,"coherent-typed-packet-metadata");
         c.AddEvidence(0.35,"distinct-workbook-signature");
         c.AddCorrelation(0.12,"bounded-network-context");
       },count:1,windowSeconds:120);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
   
 }
}
