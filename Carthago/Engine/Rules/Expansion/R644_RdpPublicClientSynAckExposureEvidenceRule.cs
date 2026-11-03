// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 executed. Workbook R2472.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
  /// <summary>Independent workbook R2472 candidate; no exploitation, outcome, or actor attribution.</summary>
  public sealed class R644_RdpPublicClientSynAckExposureEvidenceRule : EvidenceDrivenPrecisionRuleBase
  {
    private static readonly RuleDescriptor Rule = new(
      RuleId:"R644",Name:"Internal RDP listener SYN-ACK response to public client",Category:"IdentityAccess",
      Description:"Internal RDP listener SYN-ACK response to public client. Observed evidence only; An SYN-ACK proves network handshake response only, not authenticated RDP access or true external Internet exposure through NAT.",
      DefaultSeverity:SeverityLevel.Medium,ConfigKey:"Rules.R644.Enabled",EnabledByDefault:true);
    private static readonly RulePrecisionProfile Profile=CreateEvidenceDrivenProfile(new PrecisionRuleSpec
    {
      RuleId="R644",Name="Internal RDP listener SYN-ACK response to public client",Category="IdentityAccess",
      Description="Source-only candidate from R2472: An SYN-ACK proves network handshake response only, not authenticated RDP access or true external Internet exposure through NAT.",
      Severity=SeverityLevel.Medium,Maturity=RulePrecisionMaturity.Candidate,RuntimeMode=RuleRuntimeMode.Shadow,
      RequiredTelemetry=new[]{RuleTelemetryKind.Flow,RuleTelemetryKind.Flow},
      RequiredFields=new[]{"source","destination_or_host","protocol_or_port","tcp.flags","source.port"},
      EvidenceFields=new[]{"matched_conditions","research.identifier","outcome"},
      PositiveConditions=new[]
      {
        "Only typed packet metadata and this rule's independent exact predicate can satisfy the candidate.",
        "Use parser-backed HTTP/DNS/OT fields or explicitly conditional process/TCP metadata, with coherent endpoints.",
        "An observed request, query, connection attempt or SYN-ACK is not an authenticated security outcome."
      },
      NegativeConditions=new[]
      {
        "Reject missing producer fields, contradictory transport, generic port-only or Info-only evidence.",
        "Reject benign near misses, packet duplicates, stale time and cooldown repeats.",
        "Never claim successful exploitation, credential disclosure, actor attribution or established tunnel."
      },
      FalsePositives=new[]{"An SYN-ACK proves network handshake response only, not authenticated RDP access or true external Internet exposure through NAT."},
      MinimumConfidence=82,WindowThreshold=1,
      Window=TimeSpan.FromMinutes(5),Cooldown=TimeSpan.FromMinutes(10),
      DistinctBy="rule_specific_typed_observation_exact_peer_or_bounded_window",
      TuningKnobs=new[]{"Mode","ApprovedAdminHosts","ApprovedMaintenanceWindows","ApprovedScanners"},
      RequiredTests=new[]{"exact positive and benign near miss","missing/contradictory protocol or metadata",
        "duplicate IDs, expired time, cooldown","safe redacted evidence and honest scope",
        "candidate shadow policy, independent registry registration"}
    });
    private readonly WebSignatureCooldown _cooldown=new();
    public R644_RdpPublicClientSynAckExposureEvidenceRule():base(Rule,Profile){}

    protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
    {
      var r=context.Record;
      if(!Specific(r))return NoMatch();
      var observed=_cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
      if(observed==WebSignatureObservation.None)return NoMatch();
      if(observed==WebSignatureObservation.Suppressed)return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
      var evidence=new[]
      {
        new DetectionEvidenceItem("research.identifier","workbook.R2472","source-research"),
        new DetectionEvidenceItem("matched_conditions","independent_rdpsynack_predicate","rule"),
        new DetectionEvidenceItem("outcome","tcp_syn_ack_only_unknown","rule")
      };
      var evt=CreateDetectionEvent(context,SeverityLevel.Medium,
        "Observed Internal RDP listener SYN-ACK response to public client; no authenticated outcome established",
        evidence,confidence=>{
          confidence.AddEvidence(0.45,"bounded-observed-rdpsynack-metadata");
          confidence.AddEvidence(0.34,"specific-workbook-shape");
          confidence.AddCorrelation(0.12,"coherent-typed-observation");
        },count:1,windowSeconds:300);
      
      return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
    }
    private static bool Specific(TrafficRecord r){
 if(r.Id==Guid.Empty||r.IpVersion!=4||!r.IsTcp||r.IsUdp||r.IsQuic||r.SourcePort!=3389
 ||r.DestinationPort is null or <=0 or >65535||r.TcpFlags!=0x12||r.Length<40
 ||!string.Equals(r.Protocol,"TCP",StringComparison.OrdinalIgnoreCase)
 ||r.HttpMethod!=null||r.DnsQname!=null||r.TlsVersion!=null
 ||!IPAddress.TryParse(r.Source,out var src)||!IPAddress.TryParse(r.Destination,out var dst))return false;
 return Private(src)&&Public(dst);
 }private static bool Private(IPAddress a){if(a.AddressFamily!=AddressFamily.InterNetwork)return false;var b=a.GetAddressBytes();return b[0]==10||(b[0]==172&&b[1]>=16&&b[1]<=31)||(b[0]==192&&b[1]==168);}
private static bool Public(IPAddress a){if(a.AddressFamily!=AddressFamily.InterNetwork)return false;var b=a.GetAddressBytes();return b[0]!=0&&b[0]!=10&&b[0]!=127&&b[0]<224&&!(b[0]==169&&b[1]==254)&&!(b[0]==100&&b[1]>=64&&b[1]<=127)&&!(b[0]==172&&b[1]>=16&&b[1]<=31)&&!(b[0]==192&&(b[1]==168||b[1]==0||b[1]==88&&b[2]==99))&&!(b[0]==198&&(b[1]==18||b[1]==19||b[1]==51&&b[2]==100))&&!(b[0]==203&&b[1]==0&&b[2]==113);}

  }
}
