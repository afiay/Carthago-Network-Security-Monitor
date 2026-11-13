// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2797 / AN2244.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R978_PrivateModbusBulkFileReadResponseRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R978", Name: "Modbus bulk file-record response to public client", Category: "IotOtAdvanced",
            Description: "Private IPv4 TCP/502 server returns a transaction-matched FC20 file-record response of 100–120 registers to a public client. Content sensitivity, authorization and operational baseline unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R978.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R978", Name = "Modbus bulk file-record response to public client", Category = "IotOtAdvanced",
            Description = "workbook.R2797 AN2244: exact one-record bulk request and response, not proof of configuration/program retrieval or unauthorized collection.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "modbus.bulk_file_read_response.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete SYN/SYN-ACK and first same-flow FC20 reference-6 single record request for 100–120 registers and exact matching non-exception response, same transaction/unit, sequence/ACK contiguous, <=30 seconds." },
            NegativeConditions = new[] { "Shorter/out-of-subset reads, other functions, exception or wrong response lengths, transaction/unit mismatch, missing request, partial/coalesced traffic, wrong scope, stale or contradictory evidence fail closed." },
            FalsePositives = new[] { "Authorized backup, commissioning and diagnostics may retrieve file records. Requested volume alone is not an anomaly baseline." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(30),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "private_modbus_server_public_client_bulk_file_read",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw capture quantity/range boundaries", "benign and malformed request/response controls",
                "transaction/unit/flow identity and TCP sequence", "timeout/reset/retransmission and scope",
                "forged evidence, cooldown, isolation, privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R978_PrivateModbusBulkFileReadResponseRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r) ||
                r.SourcePort != 502 || r.DestinationPort == 502 ||
                r.L4Len is not (>= 211 and <= 251) ||
                !r.ModbusBulkFileReadResponseObserved || r.ModbusOversizedReadExceptionObserved ||
                r.ModbusSingleRegisterWritePoint.HasValue || r.DnsQname != null || r.DnsIsResponse ||
                r.HttpUri != null || r.HttpMethod != null || r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2797", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_same_transaction_bulk_fc20_file_record_response", "rule"),
                new DetectionEvidenceItem("outcome", "file_record_response_observed_content_authorization_and_baseline_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Private Modbus server returned a bulk file record to a public client; content, authorization and operational baseline unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_modbus_file_read_and_matching_response");
                    confidence.AddEvidence(0.35, "private_server_public_client_boundary");
                }, count: 1, windowSeconds: 30);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
