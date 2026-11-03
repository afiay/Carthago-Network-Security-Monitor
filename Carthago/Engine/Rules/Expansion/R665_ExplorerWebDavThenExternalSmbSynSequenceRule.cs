// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, 0 executed. Workbook R1332.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Independent Explorer WebDAV-like GET followed by SMB SYN to same public peer; no success, identity or exfiltration inference.</summary>
 public sealed class R665_ExplorerWebDavThenExternalSmbSynSequenceRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
     RuleId:"R665",Name:"Explorer WebDAV-like GET followed by SMB SYN to same public peer",Category:"LateralMovement",
     Description:"Explorer WebDAV-like GET followed by SMB SYN to same public peer. R174 observes inbound WebDAV abuse; R351 requires NTLM-attributed telemetry. This candidate observes only two ordered outbound network attempts, never credential coercion.",
     DefaultSeverity:SeverityLevel.Medium,
     ConfigKey:"Rules.R665.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R665",Name="Explorer WebDAV-like GET followed by SMB SYN to same public peer",Category="LateralMovement",Description="R174 observes inbound WebDAV abuse; R351 requires NTLM-attributed telemetry. This candidate observes only two ordered outbound network attempts, never credential coercion.",
     Severity=SeverityLevel.Medium,
     Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Http},
     RequiredFields=new[]{"source","destination_or_host","http.method","http.uri","process.id"},
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
     FalsePositives=new[]{"Authorized developer workflows, management clients, automated scripts or normal network operations may match. R174 observes inbound WebDAV abuse; R351 requires NTLM-attributed telemetry. This candidate observes only two ordered outbound network attempts, never credential coercion."},
     MinimumConfidence=82,
     WindowThreshold=2,
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
   private readonly Research656WebdavThenSmb _webdav=new();
   public R665_ExplorerWebDavThenExternalSmbSynSequenceRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     var proc=NetworkBatch266270Evidence.Process(r);
if(r.ProcessId<=0||proc is not ("explorer.exe" or "winword.exe" or "excel.exe")
||!Research656Evidence.PrivatePublic(r,true))return NoMatch();
var first=WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)
&&method=="GET"&&(uri.Contains("/dav/",StringComparison.OrdinalIgnoreCase)
||uri.Contains("/webdav/",StringComparison.OrdinalIgnoreCase)
||uri.Contains("/remote.php/dav",StringComparison.OrdinalIgnoreCase));
var second=Research656Evidence.NativeTcp(r,true)&&r.DestinationPort==445
&&r.TcpFlags==0x02 && r.L4Len is null or 0 &&r.ApplicationProtocol==null
&&r.HttpMethod==null;
if(!first&&!second)return NoMatch();
if(!_webdav.Observe(r.Source+"|"+r.Destination+"|"+r.ProcessId+"|"+proc,
r.Id,context.TimestampUtc,first))
return NoMatch();
     var seen=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(seen==WebSignatureObservation.None)return NoMatch();
     if(seen==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1332","owner-research"),
       new DetectionEvidenceItem("matched_conditions","webdav_shape","rule"),
       new DetectionEvidenceItem("outcome","webdav_smb_attempt_sequence_no_ntlm_proof","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "Explorer WebDAV-like GET followed by SMB SYN to same public peer observed; response, authorization and security outcome unknown",
       evidence,c=>{
         c.AddEvidence(0.43,"typed-producer-input");
         c.AddEvidence(0.35,"independent-workbook-predicate");
         c.AddCorrelation(0.12,"coherent-observation");
       },count:2,windowSeconds:300);
     
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
   
 }
}
