// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2790 / AN2288.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R974_PrivateModbusOversizedReadExceptionRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R974", Name: "Modbus oversized FC03 read rejected by private server", Category: "IotOtAdvanced",
            Description: "Private IPv4 TCP/502 server returns exact Illegal Data Value exception to a complete same-connection public client function 03 request exceeding 125 registers. Authorization, exploit intent and device impact unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R974.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R974", Name = "Modbus oversized FC03 read rejected by private server", Category = "IotOtAdvanced",
            Description = "workbook.R2790 AN2288: exact oversized FC03 request and transaction-matched exception 03, not proof of exploitation.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "modbus.oversized_read_exception.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete IPv4 TCP SYN/SYN-ACK and exact first FC03 request quantity 126–65535 followed by exact matching 0x83/0x03 response; transaction/unit match, sequence/ACK contiguous, <=30 seconds." },
            NegativeConditions = new[] { "Valid or zero quantity, other function/exception, mismatched transaction/unit, missing request, partial/coalesced packets, wrong scope, stale or contradictory evidence fail closed." },
            FalsePositives = new[] { "Misconfigured polling, authorized robustness testing and programming defects can produce this rejected request." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(30),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "private_modbus_server_public_client_oversized_read_exception",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw capture quantity boundaries", "benign and malformed request/response controls",
                "transaction/unit/flow identity and TCP sequence", "timeout/reset/retransmission and scope",
                "forged evidence, cooldown, isolation, privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R974_PrivateModbusOversizedReadExceptionRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r) ||
                r.SourcePort != 502 || r.DestinationPort == 502 || r.L4Len != 9 ||
                !r.ModbusOversizedReadExceptionObserved || r.ModbusSingleRegisterWritePoint.HasValue ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2790", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_same_transaction_oversized_fc03_exception_03", "rule"),
                new DetectionEvidenceItem("outcome", "server_exception_observed_exploit_intent_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Private Modbus server rejected a public client's oversized FC03 read request with exception 03; authorization, exploit intent and impact unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_modbus_request_and_matching_exception");
                    confidence.AddEvidence(0.35, "private_server_public_client_boundary");
                }, count: 1, windowSeconds: 30);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
