// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, 0 executed. Workbook R1497.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Independent Attributed Git smart-HTTP push request to official code host; no success, identity or exfiltration inference.</summary>
 public sealed class R656_OfficialGitRemoteProcessSmartHttpPushRequestRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
     RuleId:"R656",Name:"Attributed Git smart-HTTP push request to official code host",Category:"CloudDev",
     Description:"Attributed Git smart-HTTP push request to official code host. R207 requires a first-seen unofficial remote host; this candidate requires a Git-attributed request to official GitHub/GitLab with /git-receive-pack, not a repository-exfiltration outcome.",
     DefaultSeverity:SeverityLevel.Medium,
     ConfigKey:"Rules.R656.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R656",Name="Attributed Git smart-HTTP push request to official code host",Category="CloudDev",Description="R207 requires a first-seen unofficial remote host; this candidate requires a Git-attributed request to official GitHub/GitLab with /git-receive-pack, not a repository-exfiltration outcome.",
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
     FalsePositives=new[]{"Authorized developer workflows, management clients, automated scripts or normal network operations may match. R207 requires a first-seen unofficial remote host; this candidate requires a Git-attributed request to official GitHub/GitLab with /git-receive-pack, not a repository-exfiltration outcome."},
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
   
   public R656_OfficialGitRemoteProcessSmartHttpPushRequestRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)||method!="POST"
||!Research656Evidence.PrivatePublic(r,true)
||!Research656Evidence.ValidProcess(r,"git.exe","git")
||!(Research656Evidence.HostIs(r.HttpHost,"github.com")||Research656Evidence.HostIs(r.HttpHost,"gitlab.com"))
||!uri.Split('?')[0].EndsWith("/git-receive-pack",StringComparison.OrdinalIgnoreCase))
return NoMatch();
     var seen=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(seen==WebSignatureObservation.None)return NoMatch();
     if(seen==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1497","owner-research"),
       new DetectionEvidenceItem("matched_conditions","git_shape","rule"),
       new DetectionEvidenceItem("outcome","git_push_request_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "Attributed Git smart-HTTP push request to official code host observed; response, authorization and security outcome unknown",
       evidence,c=>{
         c.AddEvidence(0.43,"typed-producer-input");
         c.AddEvidence(0.35,"independent-workbook-predicate");
         c.AddCorrelation(0.12,"coherent-observation");
       },count:1,windowSeconds:300);
     
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
   
 }
}
