// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R2799.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R708_PublicClientTftpExchangeToPrivateHostRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R708",
            Name: "Public client TFTP request followed by private-host transfer reply",
            Category: "IotOtAdvanced",
            Description: "Public client to private server: capture-attested TFTP RRQ or WRQ followed by its exact first DATA block 1 or ACK block 0 within 30 seconds. No transfer completion, file identity, firmware change, authorization or compromise established.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R708.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R708",
            Name = "Public client TFTP request followed by private-host transfer reply",
            Category = "IotOtAdvanced",
            Description = "Workbook R2799: capture-attested TFTP initial request and protocol-consistent first reply, linked to the original request ID and reverse tuple. The full firmware/configuration and authorization analytic remains unsupported.",
            Severity = SeverityLevel.Medium,
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
            FalsePositives = new[] { "Approved remote provisioning, PXE/TFTP administration, recovery, lab activity, and device maintenance can look identical at flow level." },
            MinimumConfidence = 82,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(30),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "public_client+private_tftp_host+client_port",
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

        public R708_PublicClientTftpExchangeToPrivateHostRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            var request = Research786NetworkEvidence.PublicPrivate(r) && TftpQualifiedEvidence.Request(r);
            var reply = Research786NetworkEvidence.PrivatePublic(r) && TftpQualifiedEvidence.FirstReply(r);
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
                new DetectionEvidenceItem("research.identifier", "workbook.R2799", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_to_private_tftp_request_reply_pair", "rule"),
                new DetectionEvidenceItem("outcome", "inbound_tftp_initial_exchange_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Public-client TFTP initial request and exact first server response observed; firmware mode, file identity and transfer completion unknown.",
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
