// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, 0 executed. Research R2475.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
  /// <summary>Independent workbook R2475 predicate; observational only.</summary>
  public sealed class R629_HybridConnectionManagerServiceBusDnsRule : EvidenceDrivenPrecisionRuleBase
  {
    private static readonly RuleDescriptor Rule=new(
      RuleId:"R629", Name:"Hybrid Connection Manager DNS lookup to Azure Service Bus",Category:"DnsAdvanced",
      Description:"Original R2475; R620 LocaltoNet domain alone; here an exact local process + DNS query conjunction, benign Azure connector likely. Only observable packet fields, no asserted outcome.",
      DefaultSeverity:SeverityLevel.Low,
      ConfigKey:"Rules.R629.Enabled",EnabledByDefault:true);
    private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
    {
      RuleId="R629",Name="Hybrid Connection Manager DNS lookup to Azure Service Bus",Category="DnsAdvanced",
      Description="Narrowed source candidate from R2475. R620 LocaltoNet domain alone; here an exact local process + DNS query conjunction, benign Azure connector likely",
      Severity=SeverityLevel.Low,Maturity=RulePrecisionMaturity.Candidate,
      RuntimeMode=RuleRuntimeMode.Shadow,
      RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Dns,RuleTelemetryKind.Process},
      RequiredFields=new[]{"source","destination_or_host","protocol_or_port","dns_qname","process.name","process.id"},
      EvidenceFields=new[]{"dns.signature","matched_conditions","outcome"},
      PositiveConditions=new[]
      {
        "Require real structured packet/flow fields and the independent exact candidate predicate.",
        "A matching request, DNS lookup or process-associated flow is not authenticated outcome evidence.",
        "Only a bounded metadata signature is emitted, without unredacted request content."
      },
      NegativeConditions=new[]
      {
        "Reject missing or contradictory transport, absent parser context or absent local process identity.",
        "Reject ordinary near misses, duplicate IDs, out-of-order time and cooldown repeats.",
        "No CVE exploitation, domain attribution, tunnel creation or command execution is inferred."
      },
      FalsePositives=new[]{"Best-effort Windows PID attribution or normal management tools can resemble the behavior."},
      MinimumConfidence=78,
      WindowThreshold=1,Window=TimeSpan.FromMinutes(5),Cooldown=TimeSpan.FromMinutes(10),
      DistinctBy="exact_source_destination_and_independent_signature",
      TuningKnobs=new[]{"Mode","ApprovedAdminHosts","ApprovedScanners","ApprovedMaintenanceWindows"},
      RequiredTests=new[]{"specific positive and near-miss negative","missing and contradictory fields",
        "duplicate IDs and cooldown","privacy and honest unverified outcome",
        "Candidate Shadow mode and uniqueness"}
    });
    private readonly WebSignatureCooldown _cooldown=new();
    public R629_HybridConnectionManagerServiceBusDnsRule():base(Rule,Profile){}
    protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
    {
      var r=context.Record;
      if(!DnsSignatureRequestEvidence.TryGetQuery(r,out var query)||!ProcessSignatureEvidence.TryDnsOwner(r,out var p)||p!="hybridconnectionmanager.exe"||!ProcessSignatureEvidence.EndsIn(query,"servicebus.windows.net"))return NoMatch();
      var state=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
      if(state==WebSignatureObservation.None)return NoMatch();
      if(state==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
      var evidence=new[]
      {
        new DetectionEvidenceItem("dns.signature","workbook.R2475.dns","bounded-record-metadata"),
        new DetectionEvidenceItem("matched_conditions","independent_dns_shape","rule"),
        new DetectionEvidenceItem("outcome","dns_process_identity_unverified","rule")
      };
      var evt=CreateDetectionEvent(context,SeverityLevel.Low,
        "Service Bus DNS lookup by a candidate local process observed; attribution requires confirmation",evidence, confidence=>
        {
          confidence.AddEvidence(0.44,"structured-dns-metadata");
          confidence.AddEvidence(0.35,"distinct-workbook-predicate");
          confidence.AddCorrelation(0.12,"coherent-source-destination");
        },count:1,windowSeconds:300);
      DnsSignatureRequestEvidence.RedactQuery(evt,query);
      return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
    }
    
  }
}
