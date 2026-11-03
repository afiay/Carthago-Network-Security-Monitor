// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed. Workbook R2706.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 /// <summary>Public-client EtherNet/IP ListIdentity multi-host probe; no outcome, identity or authorization inferred.</summary>
 public sealed class R655_PublicEtherNetIpListIdentityHostSweepRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
    RuleId:"R655", Name:"Public-client EtherNet/IP ListIdentity multi-host probe",Category:"IotOtAdvanced",
    Description:"Public-client EtherNet/IP ListIdentity multi-host probe. R488 generic CIP ListIdentity burst and R643 internal sequential scan; this is public-to-private fanout to three exact hosts.",
    DefaultSeverity:SeverityLevel.Medium,
    ConfigKey:"Rules.R655.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
    RuleId="R655",Name="Public-client EtherNet/IP ListIdentity multi-host probe",Category="IotOtAdvanced",
    Description="R488 generic CIP ListIdentity burst and R643 internal sequential scan; this is public-to-private fanout to three exact hosts.",
    Severity=SeverityLevel.Medium,
    Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
    RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.OtIcsProtocol},
    RequiredFields=new[]{"source","destination_or_host","protocol_or_port","application_protocol","destination_port"},
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
    FalsePositives=new[]{"Authorized maintenance, vulnerability assessment, application management or ordinary named-process use may match. R488 generic CIP ListIdentity burst and R643 internal sequential scan; this is public-to-private fanout to three exact hosts."},
    MinimumConfidence=84,
    WindowThreshold=3,Window=TimeSpan.FromMinutes(5),
    Cooldown=TimeSpan.FromMinutes(10),
    DistinctBy="independent_rule_specific_source_and_destination_or_subnet",
    TuningKnobs=new[]{"Mode","ApprovedAdminHosts","ApprovedScanners","ApprovedMaintenanceWindows"},
    RequiredTests=new[]{"exact positive and benign near miss","missing or contradictory transport and parser fields",
    "unique IDs, out-of-order observations, expiry and cooldown","redacted evidence, no outcome inference",
    "registry uniqueness and Candidate Shadow policy"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   private readonly Research646DistinctWindow _window=new();
   public R655_PublicEtherNetIpListIdentityHostSweepRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!Research646Evidence.Tcp(r,true)
  ||r.DestinationPort!=44818
  ||!string.Equals(r.ApplicationProtocol,"ethernetip.listidentity",StringComparison.Ordinal)
  ||!Research646Evidence.Pair(r,true,out _,out var dst)
  ||!_window.Observe(r.Source+"|"+Research646Evidence.Subnet24(dst),
       dst.ToString(),r.Id,context.TimestampUtc))return NoMatch();
     var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(observed==WebSignatureObservation.None)return NoMatch();
     if(observed==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var evidence=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R2706","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_ot_cip_shape","rule"),
       new DetectionEvidenceItem("outcome","cip_listidentity_request_fanout_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "Public-client EtherNet/IP ListIdentity multi-host probe observed; outcome and authorization unverified",
       evidence,c=>{
         c.AddEvidence(0.43,"typed-network-or-parser-evidence");
         c.AddEvidence(0.36,"independent-workbook-signature");
         c.AddCorrelation(0.12,"coherent-typed-source-and-destination");
       },count:3,windowSeconds:300);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
 }
}
