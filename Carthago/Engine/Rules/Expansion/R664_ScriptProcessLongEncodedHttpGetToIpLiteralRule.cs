// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, 0 executed. Workbook R1977.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Independent Script process GET carrying a long encoded query to public IP literal; no success, identity or exfiltration inference.</summary>
 public sealed class R664_ScriptProcessLongEncodedHttpGetToIpLiteralRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
     RuleId:"R664",Name:"Script process GET carrying a long encoded query to public IP literal",Category:"HttpApi",
     Description:"Script process GET carrying a long encoded query to public IP literal. R019 is generic encoded/long URI, while this requires a script process/PID, exact IP literal HTTP host, GET and explicit long URL-safe query parameter.",
     DefaultSeverity:SeverityLevel.Medium,
     ConfigKey:"Rules.R664.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R664",Name="Script process GET carrying a long encoded query to public IP literal",Category="HttpApi",Description="R019 is generic encoded/long URI, while this requires a script process/PID, exact IP literal HTTP host, GET and explicit long URL-safe query parameter.",
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
     FalsePositives=new[]{"Authorized developer workflows, management clients, automated scripts or normal network operations may match. R019 is generic encoded/long URI, while this requires a script process/PID, exact IP literal HTTP host, GET and explicit long URL-safe query parameter."},
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
   
   public R664_ScriptProcessLongEncodedHttpGetToIpLiteralRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)||method!="GET"
||!Research656Evidence.PrivatePublic(r,true)
||!Research656Evidence.ValidProcess(r,"powershell.exe","pwsh.exe","regsvr32.exe","mshta.exe")
||!System.Net.IPAddress.TryParse(r.HttpHost,out var hostIp)
||!System.Net.IPAddress.TryParse(r.Destination,out var targetIp)||!hostIp.Equals(targetIp)
||!ContainsEncodedParameter(uri))
return NoMatch();
     var seen=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(seen==WebSignatureObservation.None)return NoMatch();
     if(seen==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1977","owner-research"),
       new DetectionEvidenceItem("matched_conditions","encoded_shape","rule"),
       new DetectionEvidenceItem("outcome","encoded_http_get_request_only","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "Script process GET carrying a long encoded query to public IP literal observed; response, authorization and security outcome unknown",
       evidence,c=>{
         c.AddEvidence(0.43,"typed-producer-input");
         c.AddEvidence(0.35,"independent-workbook-predicate");
         c.AddCorrelation(0.12,"coherent-observation");
       },count:1,windowSeconds:300);
     
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
   private static bool ContainsEncodedParameter(string uri)
{
 var i=uri.IndexOf("?data=",StringComparison.OrdinalIgnoreCase);
 if(i<0)i=uri.IndexOf("&data=",StringComparison.OrdinalIgnoreCase);
 if(i<0)return false;
 var start=i+6;var end=uri.IndexOf('&',start);if(end<0)end=uri.Length;
 var count=end-start;if(count<80||count>512)return false;
 var diversity=0;var digits=0;var letters=0;
 for(var n=start;n<end;n++)
 {
  var c=uri[n];if(char.IsAsciiLetter(c)){letters++;diversity|=1;}
  else if(char.IsAsciiDigit(c)){digits++;diversity|=2;}
  else if(c is '-' or '_' or '=')diversity|=4;
  else return false;
 }
 return (diversity&3)==3&&letters>=40&&digits>=7;
}
 }
}
