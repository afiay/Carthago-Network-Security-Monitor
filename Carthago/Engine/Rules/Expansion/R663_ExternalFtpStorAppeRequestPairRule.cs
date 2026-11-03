// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, 0 executed. Workbook R1541.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Independent FTP STOR then APPE requests to same external peer; no success, identity or exfiltration inference.</summary>
 public sealed class R663_ExternalFtpStorAppeRequestPairRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
     RuleId:"R663",Name:"FTP STOR then APPE requests to same external peer",Category:"ExfiltrationAdvanced",
     Description:"FTP STOR then APPE requests to same external peer. R248 detects a single STOR/APPEND command and R652 requires script-host identity; this candidate requires both distinct request types in order.",
     DefaultSeverity:SeverityLevel.Medium,
     ConfigKey:"Rules.R663.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R663",Name="FTP STOR then APPE requests to same external peer",Category="ExfiltrationAdvanced",Description="R248 detects a single STOR/APPEND command and R652 requires script-host identity; this candidate requires both distinct request types in order.",
     Severity=SeverityLevel.Medium,
     Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Payload},
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
     FalsePositives=new[]{"Authorized developer workflows, management clients, automated scripts or normal network operations may match. R248 detects a single STOR/APPEND command and R652 requires script-host identity; this candidate requires both distinct request types in order."},
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
   private readonly Research656DistinctWindow _distinct=new();
   public R663_ExternalFtpStorAppeRequestPairRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!NetworkBatch246250Evidence.FtpUpload(r)
||r.HttpMethod!=null||r.DnsQname!=null||r.TlsVersion!=null
||!_distinct.Observe(r.Source+"|"+r.Destination,
r.ApplicationProtocol=="ftp.stor"?"STOR":r.ApplicationProtocol=="ftp.appe"?"APPE":"OTHER",
r.Id,context.TimestampUtc,2))return NoMatch();
     var seen=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(seen==WebSignatureObservation.None)return NoMatch();
     if(seen==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1541","owner-research"),
       new DetectionEvidenceItem("matched_conditions","ftp_shape","rule"),
       new DetectionEvidenceItem("outcome","ftp_request_pair_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "FTP STOR then APPE requests to same external peer observed; response, authorization and security outcome unknown",
       evidence,c=>{
         c.AddEvidence(0.43,"typed-producer-input");
         c.AddEvidence(0.35,"independent-workbook-predicate");
         c.AddCorrelation(0.12,"coherent-observation");
       },count:2,windowSeconds:300);
     
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
   
 }
}
