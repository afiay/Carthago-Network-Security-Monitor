// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit authored, zero executed. Workbook R1716.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 public sealed class R677_TlsClientHelloOnDnsOrAltHttpPortRule : EvidenceDrivenPrecisionRuleBase
 {
   private static readonly RuleDescriptor Rule=new(
    RuleId:"R677",Name:"Outbound TLS observation on DNS port 53 or alternate HTTP port 8080",Category:"TlsPki",
    Description:"Outbound TLS observation on DNS port 53 or alternate HTTP port 8080; Unusual TLS port alone does not establish a tunnel, certificate abuse or encrypted C2.",
    DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R677.Enabled",EnabledByDefault:true);
   private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
   {
     RuleId="R677",Name="Outbound TLS observation on DNS port 53 or alternate HTTP port 8080",Category="TlsPki",
     Description="Workbook R1716. R669 requires a named system utility and TLS on port 80, not TLS on 53/8080; R151 checks HTTP/2 ALPN. Unusual TLS port alone does not establish a tunnel, certificate abuse or encrypted C2.",
     Severity=SeverityLevel.Medium,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
     RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Tls},
     RequiredFields=new[]{"source","destination_or_host","protocol_or_port","tls.sni","tls.version"},
     EvidenceFields=new[]{"research.identifier","matched_conditions","outcome"},
     PositiveConditions=new[]{
       "Require coherent typed transport/parser observations and this independent rule predicate.",
       "If a sequence is required, use a bounded per-instance window of unique packet IDs.",
       "Events describe observed request/response/flow shape, not authenticated security outcomes."
     },
     NegativeConditions=new[]{
       "Reject missing or contradictory producer fields and out-of-scope ports/directions.",
       "Reject similar-but-benign near misses, packet ID replays, stale/out-of-order time and cooldown repeats.",
       "Do not infer a device identity, command execution, approved exposure, C2 tunnel or credential compromise."
     },
     FalsePositives=new[]{"Authorized management, network inventory, diagnostics and security testing may resemble this signal. Unusual TLS port alone does not establish a tunnel, certificate abuse or encrypted C2."},
     MinimumConfidence=82,WindowThreshold=1,Window=TimeSpan.FromMinutes(5),
     Cooldown=TimeSpan.FromMinutes(10),DistinctBy="independent_rule_specific_ip_peer_or_bounded_window",
     TuningKnobs=new[]{"Mode","ApprovedManagementHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
     RequiredTests=new[]{"exact positive and benign near miss","wrong method/port/direction/producer",
       "source and destination correlation, out-of-order and duplicate IDs",
       "event evidence privacy, bounded state and cooldown",
       "Candidate Shadow rule identity and registry uniqueness"}
   });
   private readonly WebSignatureCooldown _cooldown=new();
   
   public R677_TlsClientHelloOnDnsOrAltHttpPortRule():base(Rule,Profile){}
   protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
   {
     var r=context.Record;
     if(!Research676Evidence.Tcp(r)||!Research676Evidence.PrivateToPublic(r)
 ||r.DestinationPort is not (53 or 8080)||r.TlsVersion==null||string.IsNullOrWhiteSpace(r.Sni)
 ||r.L4Len is null or <24 or >4096||r.HttpMethod!=null||r.DnsQname!=null
 ||r.ApplicationProtocol=="DNS"||r.ApplicationProtocol=="HTTP")return NoMatch();
     var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
     if(observed==WebSignatureObservation.None)return NoMatch();
     if(observed==WebSignatureObservation.Suppressed)
       return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
     var items=new[]{
       new DetectionEvidenceItem("research.identifier","workbook.R1716","owner-research"),
       new DetectionEvidenceItem("matched_conditions","independent_tls_typed_shape","rule"),
       new DetectionEvidenceItem("outcome","nonstandard_tls_port_only_unknown","rule")
     };
     var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
       "Outbound TLS observation on DNS port 53 or alternate HTTP port 8080 observed; Unusual TLS port alone does not establish a tunnel, certificate abuse or encrypted C2.",
       items,c=>{
         c.AddEvidence(0.43,"typed-transport-and-endpoint-fields");
         c.AddEvidence(0.34,"specific-workbook-behavior");
         c.AddCorrelation(0.12,"independent-observation-window");
       },count:1,windowSeconds:300);
     return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
   }
 }
}
