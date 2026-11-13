// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2791 / AN2184.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R976_PublicSnmpConnectionTableGetNextRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R976", Name: "Public SNMP connection-table GETNEXT request", Category: "IotOtAdvanced",
            Description: "Public IPv4 client sends a capture-validated SNMPv1/v2c GETNEXT for exactly legacy tcpConnTable and udpTable roots to private UDP/161. Authorization and returned entries unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R976.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R976", Name = "Public SNMP connection-table GETNEXT request", Category = "IotOtAdvanced",
            Description = "workbook.R2791 AN2184: exact two distinct MIB-II table-root GETNEXT bindings; no approved NMS role, operational deviation or completed walk inferred.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "destination.port", "packet.id", "snmp.connection_table_getnext.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete IPv4 UDP/161 SNMPv1/v2c GETNEXT; exactly tcpConnTable and udpTable roots in either order, empty NULL values and zero error/index." },
            NegativeConditions = new[] { "Single-table, duplicate, extra or adjacent OIDs, GET/GETBULK/SET/response, malformed BER, incomplete capture and wrong scope fail closed." },
            FalsePositives = new[] { "Authorized NMS, troubleshooting, inventory and network diagnostics can request both legacy table roots. Source policy and operational baseline are required for promotion." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "public_private_snmp_connection_table_getnext",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw capture versions and binding permutations", "single/duplicate/adjacent/extra OID and other PDU negatives",
                "BER/datagram/scope and forged evidence", "adjacent rule separation", "duplicate/reverse time/cooldown, peer isolation, privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R976_PublicSnmpConnectionTableGetNextRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.UdpData(r) || !Research786NetworkEvidence.PublicPrivate(r) ||
                r.DestinationPort != 161 || r.SourcePort == 161 || r.L4Len is not (>= 20 and <= 4096) ||
                !r.SnmpConnectionTableGetNextObserved || r.SnmpEnterpriseSetRequestObserved ||
                r.SnmpUpsRebootRequestObserved || r.SnmpHighDemandGetBulkObserved || r.SnmpSystemFingerprintGetObserved ||
                r.ApplicationProtocol != "snmp.getnext.connection_tables.request" ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2791", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_external_legacy_connection_table_getnext", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_authorization_baseline_and_returned_entries_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "External SNMP GETNEXT request for legacy TCP and UDP connection tables observed; authorization, baseline deviation and returned entries unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_exact_connection_table_getnext");
                    confidence.AddEvidence(0.35, "public_to_private_management_boundary");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
