// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, 0 executed. Workbook R2024.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Independent IDE process observed using Visual Studio developer-tunnel TLS SNI; no success, identity or exfiltration inference.</summary>
 public sealed class R662_IdeProcessVisualStudioDevTunnelTlsSniEgressRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
     RuleId:"R662",Name:"IDE process observed using Visual Studio developer-tunnel TLS SNI",Category:"EvasionTunnel",
     Description:"IDE process observed using Visual Studio developer-tunnel TLS SNI. R516/R517 handle other tunneling providers; this exact Visual Studio development-tunnel SNI and IDE process conjunction differs.",
     DefaultSeverity:SeverityLevel.Low,
     ConfigKey:"Rules.R662.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R662",Name="IDE process observed using Visual Studio developer-tunnel TLS SNI",Category="EvasionTunnel",Description="R516/R517 handle other tunneling providers; this exact Visual Studio development-tunnel SNI and IDE process conjunction differs.",
     Severity=SeverityLevel.Low,
     Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Tls,RuleTelemetryKind.Process},
     RequiredFields=new[]{"source","destination_or_host","process.name","process.id","network.destinationPort"},
     EvidenceFields=new[]{"research.identifier","matched_conditions","outcome"},
     PositiveConditions=new[]{
       "Require observed typed source/destination and the individual workbook-derived predicate.",
       "Process/PID association is best-effort and does not establish authenticated executable identity.",
       "Request, query, port probe and connection-shape outcomes remain unverified."
     },
     NegativeConditions=new[]{
       "Reject missing or conflicting protocol, wrong method or port, or unparsed Info-only assertions.",
       "Reject unrelated benign near misses, duplicate IDs, stale timestamps, and cooldown repeats.",
       "Do not infer credential disclosure, exfiltration, successful Git push, authentication, or tunnel setup."
     },
     FalsePositives=new[]{"Authorized developer workflows, management clients, automated scripts or normal network operations may match. R516/R517 handle other tunneling providers; this exact Visual Studio development-tunnel SNI and IDE process conjunction differs."},
     MinimumConfidence=82,
     WindowThreshold=1,
     Window=TimeSpan.FromMinutes(5),Cooldown=TimeSpan.FromMinutes(10),
     DistinctBy="specific_rule_process_peer_tuple_or_bounded_sequence",
     TuningKnobs=new[]{"Mode","ApprovedHosts","ApprovedMaintenanceWindows","ApprovedProcesses"},
     RequiredTests=new[]{
       "positive evidence and rule-specific benign near miss",
       "wrong/missing parser or process fields; public/private boundary",
       "duplicate observations and out-of-order timestamps",
       "expiry and bounded state; cooldown; fixed evidence privacy",
       "Shadow Candidate and unique sequential registry"
     }
   });
   private readonly WebSignatureCooldown _cooldown=new();
   
   public R662_IdeProcessVisualStudioDevTunnelTlsSniEgressRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!NetworkBatch266270Evidence.ProcessEgress(r,out var p)
||p is not ("code.exe" or "code-insiders.exe" or "jetbrains-client.exe" or "idea64.exe")
||r.TlsVersion==null||r.Sni==null||r.HttpMethod!=null
||!(Research656Evidence.HostIs(r.Sni,"devtunnels.ms")
||Research656Evidence.HostIs(r.Sni,"tunnels.api.visualstudio.com")))
return NoMatch();
     var seen=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(seen==WebSignatureObservation.None)return NoMatch();
     if(seen==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R2024","owner-research"),
       new DetectionEvidenceItem("matched_conditions","ide_shape","rule"),
       new DetectionEvidenceItem("outcome","ide_dev_tunnel_sni_only","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Low,
       "IDE process observed using Visual Studio developer-tunnel TLS SNI observed; response, authorization and security outcome unknown",
       evidence,c=>{
         c.AddEvidence(0.43,"typed-producer-input");
         c.AddEvidence(0.35,"independent-workbook-predicate");
         c.AddCorrelation(0.12,"coherent-observation");
       },count:1,windowSeconds:300);
     
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
   
 }
}
