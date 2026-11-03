// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed. Workbook R1385.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Script host FTP upload command to public endpoint; no outcome, identity or authorization inferred.</summary>
 public sealed class R652_ScriptHostFtpExternalUploadRequestRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
    RuleId:"R652", Name:"Script host FTP upload command to public endpoint",Category:"ExfiltrationAdvanced",
    Description:"Script host FTP upload command to public endpoint. R248 generic FTP STOR/appe; this requires correlated local script-host process/PID and parsed request.",
    DefaultSeverity:SeverityLevel.High,
    ConfigKey:"Rules.R652.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
    RuleId="R652",Name="Script host FTP upload command to public endpoint",Category="ExfiltrationAdvanced",
    Description="R248 generic FTP STOR/appe; this requires correlated local script-host process/PID and parsed request.",
    Severity=SeverityLevel.High,
    Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
    RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Payload,RuleTelemetryKind.Process},
    RequiredFields=new[]{"source","destination_or_host","protocol_or_port","process.name","process.id","ftp.operation"},
    EvidenceFields=new[]{"research.identifier","matched_conditions","outcome"},
    PositiveConditions=new[]
    {
     "Require coherent parsed protocol/tuple and exact rule-specific packet or flow signature.",
     "Independent candidate requires distinct classification and applicable network boundary.",
     "Only an observed request or flow indication is established; authorization and outcome are unknown."
    },
    NegativeConditions=new[]
    {
     "Reject port-only assertions when an L7 parser field is required; reject missing, contradictory or malformed fields.",
     "Reject benign variants, duplicate IDs, stale windows and repeated matches during cooldown.",
     "No compromise, accepted command, authenticated service, or completed transfer is inferred."
    },
    FalsePositives=new[]{"Authorized maintenance, vulnerability assessment, application management or ordinary named-process use may match. R248 generic FTP STOR/appe; this requires correlated local script-host process/PID and parsed request."},
    MinimumConfidence=82,
    WindowThreshold=1,Window=TimeSpan.FromMinutes(5),
    Cooldown=TimeSpan.FromMinutes(10),
    DistinctBy="independent_rule_specific_source_and_destination_or_subnet",
    TuningKnobs=new[]{"Mode","ApprovedAdminHosts","ApprovedScanners","ApprovedMaintenanceWindows"},
    RequiredTests=new[]{"exact positive and benign near miss","missing or contradictory transport and parser fields",
    "unique IDs, out-of-order observations, expiry and cooldown","redacted evidence, no outcome inference",
    "registry uniqueness and Candidate Shadow policy"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   
   public R652_ScriptHostFtpExternalUploadRequestRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!NetworkBatch246250Evidence.FtpUpload(r) ||r.ProcessId<=0
 ||NetworkBatch266270Evidence.Process(r) is not ("mshta.exe" or "wscript.exe" or "cscript.exe" or "powershell.exe" or "pwsh.exe")
 ||r.HttpMethod!=null ||r.DnsQname!=null ||r.IsQuic ||r.TlsVersion!=null)return NoMatch();
     var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(observed==WebSignatureObservation.None)return NoMatch();
     if(observed==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1385","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_ftp_shape","rule"),
       new DetectionEvidenceItem("outcome","ftp_stor_command_process_identity_unverified","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.High,
       "Script host FTP upload command to public endpoint observed; outcome and authorization unverified",
       evidence,c=>{
         c.AddEvidence(0.43,"typed-network-or-parser-evidence");
         c.AddEvidence(0.36,"independent-workbook-signature");
         c.AddCorrelation(0.12,"coherent-typed-source-and-destination");
       },count:1,windowSeconds:300);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
 }
}
