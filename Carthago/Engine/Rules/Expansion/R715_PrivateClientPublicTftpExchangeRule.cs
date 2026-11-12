// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R1246.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R715_PrivateClientPublicTftpExchangeRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R715",
            Name: "Private client TFTP request followed by public-server transfer reply",
            Category: "ExfiltrationAdvanced",
            Description: "Private client to public server: capture-attested TFTP RRQ or WRQ followed by its exact first DATA block 1 or ACK block 0 within 30 seconds. No transfer completion, file identity, firmware change, authorization or compromise established.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R715.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R715",
            Name = "Private client TFTP request followed by public-server transfer reply",
            Category = "ExfiltrationAdvanced",
            Description = "Workbook R1246: capture-attested TFTP initial request and protocol-consistent first reply, linked to the original request ID and reverse tuple. The full firmware/configuration and authorization analytic remains unsupported.",
            Severity = SeverityLevel.Low,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "udp", "source.port", "destination.port", "tftp.request.opcode", "tftp.request.correlation", "tftp.reply.opcode" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require capture-attested TFTP RRQ/WRQ and protocol-consistent first response linked to the exact request.",
                "Bounded correlation uses unique packet IDs and UTC ordering where multiple observations are required.",
                "Only the observable packet, flow, parser, or best-effort process association is claimed."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory protocol fields, wrong network direction, and Info-only indicators.",
                "Reject packet-ID replay, out-of-order state, stale windows, and cooldown repeats.",
                "Do not infer authentication, exploit success, file writes, command lines, transfer completion, or compromise."
            },
            FalsePositives = new[] { "Legitimate external TFTP recovery, firmware distribution, lab provisioning, and vendor support can produce this exchange." },
            MinimumConfidence = 78,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(30),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "private_client+public_tftp_server+client_port",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive real-life-shaped case and benign near miss",
                "wrong or missing telemetry and contradictory protocol fields",
                "duplicate packet ID and out-of-order timestamp where relevant",
                "window expiry and cooldown behavior",
                "privacy/redaction, registry uniqueness, Candidate Shadow, and non-convergence"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _tftp = new();

        public R715_PrivateClientPublicTftpExchangeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            var request = Research786NetworkEvidence.PrivatePublic(r) && TftpQualifiedEvidence.Request(r);
            var reply = Research786NetworkEvidence.PublicPrivate(r) && TftpQualifiedEvidence.FirstReply(r);
            if (!request && !reply) return NoMatch();
            var key = (request ? r.Source! + "|" + r.Destination! + "|" + r.SourcePort
                : r.Destination! + "|" + r.Source! + "|" + r.DestinationPort) + "|" + r.TftpRequestCorrelationId;
            if (!_tftp.Observe(key, r.Id, context.TimestampUtc, request, 30))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1246", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "private_to_public_tftp_request_reply_pair", "rule"),
                new DetectionEvidenceItem("outcome", "outbound_tftp_initial_exchange_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Low,
                "Private-client TFTP initial request and exact first server response observed; file identity, transfer completion and exfiltration unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "capture-attested-tftp-initial-protocol");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 2,
                windowSeconds: 30);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
