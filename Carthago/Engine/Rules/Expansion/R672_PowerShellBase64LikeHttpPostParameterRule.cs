// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed. Research R1977.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Independent R1977: PowerShell POST with long Base64-like data parameter to named web host.</summary>
 public sealed class R672_PowerShellBase64LikeHttpPostParameterRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
     RuleId:"R672",Name:"PowerShell POST with long Base64-like data parameter to named web host",Category:"HttpApi",
     Description:"PowerShell POST with long Base64-like data parameter to named web host. Query characters cannot prove encoding purpose, payload content or C2.",
     DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R672.Enabled",
     EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R672",Name="PowerShell POST with long Base64-like data parameter to named web host",Category="HttpApi",
     Description="Original workbook R1977: R664 requires GET to IP literal and R253 checks Base64 in POST via its own heuristic; this requires PowerShell/PID, named public host, and exact data parameter shape.. Query characters cannot prove encoding purpose, payload content or C2.",
     Severity=SeverityLevel.Medium,
     Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Http},
     RequiredFields=new[]{"source","destination_or_host","protocol_or_port","http.method","http.uri"},
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
     FalsePositives=new[]{"Query characters cannot prove encoding purpose, payload content or C2. Legitimate tools and security testing can trigger this candidate."},
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
   
   public R672_PowerShellBase64LikeHttpPostParameterRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)||method!="POST"
||!Research666Evidence.Outbound(r)||!Research666Evidence.Process(r,"powershell.exe","pwsh.exe")
||r.HttpHost==null||System.Net.IPAddress.TryParse(r.HttpHost,out _)
||!Base64Like(uri))return NoMatch();
     var state=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(state==WebSignatureObservation.None)return NoMatch();
     if(state==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1977","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_base64_predicate","rule"),
       new DetectionEvidenceItem("outcome","base64_like_http_post_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "PowerShell POST with long Base64-like data parameter to named web host observed; process identity and security outcome unverified",
       evidence,c=>{
         c.AddEvidence(0.44,"coherent-typed-packet-metadata");
         c.AddEvidence(0.35,"distinct-workbook-signature");
         c.AddCorrelation(0.12,"bounded-network-context");
       },count:1,windowSeconds:120);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
   private static bool Base64Like(string uri)
{
 var index=uri.IndexOf("?data=",StringComparison.OrdinalIgnoreCase);
 if(index<0)index=uri.IndexOf("&data=",StringComparison.OrdinalIgnoreCase);
 if(index<0)return false;
 int start=index+6;
 int end=uri.IndexOf('&',start);if(end<0)end=uri.Length;
 if(end-start<80||end-start>600)return false;
 int letters=0,digits=0,nonAlphanumeric=0;
 for(int i=start;i<end;i++)
 {
  var c=uri[i];
  if(char.IsAsciiLetter(c))letters++;
  else if(char.IsAsciiDigit(c))digits++;
  else if(c is '+' or '/' or '-' or '_' or '=')nonAlphanumeric++;
  else return false;
 }
 return letters>=40 && digits>=8 && nonAlphanumeric>=1;
}
 }
}
