// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, 0 executed. Workbook R1984.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Independent PowerShell or script-host process to external mail-service port; no success, identity or exfiltration inference.</summary>
 public sealed class R661_ScriptHostExternalMailServiceTcpEgressRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
     RuleId:"R661",Name:"PowerShell or script-host process to external mail-service port",Category:"EvasionInfra",
     Description:"PowerShell or script-host process to external mail-service port. R020 and R313 detect generic outbound SMTP; this specifically requires a scripting process with PID and also includes IMAP/POP3 port families.",
     DefaultSeverity:SeverityLevel.Medium,
     ConfigKey:"Rules.R661.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R661",Name="PowerShell or script-host process to external mail-service port",Category="EvasionInfra",Description="R020 and R313 detect generic outbound SMTP; this specifically requires a scripting process with PID and also includes IMAP/POP3 port families.",
     Severity=SeverityLevel.Medium,
     Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Process},
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
     FalsePositives=new[]{"Authorized developer workflows, management clients, automated scripts or normal network operations may match. R020 and R313 detect generic outbound SMTP; this specifically requires a scripting process with PID and also includes IMAP/POP3 port families."},
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
   
   public R661_ScriptHostExternalMailServiceTcpEgressRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!NetworkBatch266270Evidence.ProcessEgress(r,out var p)
||p is not ("powershell.exe" or "pwsh.exe" or "rundll32.exe" or "mshta.exe" or "wscript.exe" or "cscript.exe")
||r.DestinationPort is not (25 or 465 or 587 or 110 or 143 or 993 or 995)
||r.HttpMethod!=null||r.DnsQname!=null)return NoMatch();
     var seen=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(seen==WebSignatureObservation.None)return NoMatch();
     if(seen==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1984","owner-research"),
       new DetectionEvidenceItem("matched_conditions","mail_shape","rule"),
       new DetectionEvidenceItem("outcome","mail_port_flow_only","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "PowerShell or script-host process to external mail-service port observed; response, authorization and security outcome unknown",
       evidence,c=>{
         c.AddEvidence(0.43,"typed-producer-input");
         c.AddEvidence(0.35,"independent-workbook-predicate");
         c.AddCorrelation(0.12,"coherent-observation");
       },count:1,windowSeconds:300);
     
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
   
 }
}
