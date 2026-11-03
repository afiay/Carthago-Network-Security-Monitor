// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed. Research R1988.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Independent R1988: System binary TLS ClientHello on nominal HTTP port 80.</summary>
 public sealed class R669_SystemBinaryTlsClientOnCleartextPort80Rule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
     RuleId:"R669",Name:"System binary TLS ClientHello on nominal HTTP port 80",Category:"TlsPki",
     Description:"System binary TLS ClientHello on nominal HTTP port 80. No TLS cert validation, server authentication, or protocol impersonation proof.",
     DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R669.Enabled",
     EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R669",Name="System binary TLS ClientHello on nominal HTTP port 80",Category="TlsPki",
     Description="Original workbook R1988: R151 is HTTP/2 ALPN on uncommon port and R012 general TLS heuristic; this requires unexpected TLS on TCP/80 plus exact system utility name.. No TLS cert validation, server authentication, or protocol impersonation proof.",
     Severity=SeverityLevel.Medium,
     Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Tls,RuleTelemetryKind.Process},
     RequiredFields=new[]{"source","destination_or_host","protocol_or_port","tls.sni","tls.version","process.id"},
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
     FalsePositives=new[]{"No TLS cert validation, server authentication, or protocol impersonation proof. Legitimate tools and security testing can trigger this candidate."},
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
   
   public R669_SystemBinaryTlsClientOnCleartextPort80Rule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!Research666Evidence.Outbound(r)||!Research666Evidence.Tcp(r)
||r.DestinationPort!=80||r.TlsVersion==null||string.IsNullOrWhiteSpace(r.Sni)
||r.HttpMethod!=null||r.DnsQname!=null||r.L4Len is null or <16 or >4096
||!Research666Evidence.Process(r,"rundll32.exe","mshta.exe","wscript.exe"))
return NoMatch();
     var state=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(state==WebSignatureObservation.None)return NoMatch();
     if(state==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1988","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_tls80_predicate","rule"),
       new DetectionEvidenceItem("outcome","tls_on_http_port_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "System binary TLS ClientHello on nominal HTTP port 80 observed; process identity and security outcome unverified",
       evidence,c=>{
         c.AddEvidence(0.44,"coherent-typed-packet-metadata");
         c.AddEvidence(0.35,"distinct-workbook-signature");
         c.AddCorrelation(0.12,"bounded-network-context");
       },count:1,windowSeconds:120);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
   
 }
}
