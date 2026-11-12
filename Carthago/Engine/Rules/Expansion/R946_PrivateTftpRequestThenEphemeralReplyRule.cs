// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Original workbook R1130; xUnit source authored first.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R946_PrivateTftpRequestThenEphemeralReplyRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R946", Name: "Private TFTP initial request then matched first response", Category: "IotOtAdvanced",
            Description: "Private parsed TFTP RRQ or WRQ followed by the exact capture-correlated DATA block 1 or ACK block 0 within 45 seconds. Transfer completion, filename, firmware and authorization are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R946.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R946", Name = "Private TFTP initial request then matched first response", Category = "IotOtAdvanced",
            Description = "workbook.R1130: Private parsed TFTP RRQ or WRQ followed by the exact capture-correlated DATA block 1 or ACK block 0 within 45 seconds. Transfer completion, filename, firmware and authorization are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "tftp.request.opcode", "tftp.request.correlation", "tftp.reply.opcode" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Private parsed TFTP RRQ or WRQ followed by the exact capture-correlated DATA block 1 or ACK block 0 within 45 seconds. Transfer completion, filename, firmware and authorization are unknown.", "Coherent typed IPv4 fields and independent bounded UTC observations." },
            NegativeConditions = new[] { "Wrong endpoints, missing or contradictory typed evidence, duplicate IDs, reverse UTC or expired windows fail closed.",
                "No unsupported host action, authenticated session, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, maintenance, deployment and diagnostics may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R946_PrivateTftpRequestThenEphemeralReplyRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC", "correlation expiry and isolation", "cooldown recovery", "raw Info excluded", "independent state and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R946_PrivateTftpRequestThenEphemeralReplyRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            var first = Research786NetworkEvidence.Internal(r) && r.Source != r.Destination && TftpQualifiedEvidence.Request(r);
            var second = Research786NetworkEvidence.Internal(r) && r.Source != r.Destination && TftpQualifiedEvidence.FirstReply(r);
            if (!first && !second) return NoMatch();
            var key = (first ? r.Source! + "|" + r.Destination! + "|" + r.SourcePort : r.Destination! + "|" + r.Source! + "|" + r.DestinationPort) + "|" + r.TftpRequestCorrelationId;
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1130", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R946_PrivateTftpRequestThenEphemeralReplyRule", "rule"),
                new DetectionEvidenceItem("outcome", "initial_tftp_observation_only_transfer_and_authorization_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Private TFTP initial request then matched first response observed; authorization, causality and outcome remain unverified.", evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "capture_attested_tftp_initial_protocol");
                    confidence.AddEvidence(0.33, "specific_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
