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
            Description: "A private UDP client contacts a public host on TFTP/69 and the same public host replies from an ephemeral UDP port to the original client port within 30 seconds. This does not identify a file, configuration export, upload direction, transfer completion, or exfiltration.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R715.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R715",
            Name = "Private client TFTP request followed by public-server transfer reply",
            Category = "ExfiltrationAdvanced",
            Description = "Workbook R1246: the source analytic includes configuration-file semantics and untrusted-destination policy. Carthago lacks file and CLI evidence, so this candidate is limited to an outbound cross-boundary TFTP exchange and remains separate from R708's opposite inbound direction.",
            Severity = SeverityLevel.Low,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "udp", "source.port", "destination.port" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed producer fields and this rule's independent exact predicate.",
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
        private readonly Research706TftpWindow _tftp = new();

        public R715_PrivateClientPublicTftpExchangeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research706Evidence.Udp(r)) return NoMatch();
            var request = Research706Evidence.PrivateToPublic(r) && r.DestinationPort == 69 && r.SourcePort is > 1024;
            var reply = Research706Evidence.PublicToPrivate(r) && r.SourcePort is > 1024 && r.DestinationPort is > 1024;
            if (!request && !reply) return NoMatch();
            var client = request ? r.Source! : r.Destination!;
            var server = request ? r.Destination! : r.Source!;
            var clientPort = request ? r.SourcePort!.Value : r.DestinationPort!.Value;
            if (!_tftp.Observe(client + "|" + server, request, clientPort, r.Id, context.TimestampUtc))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1246", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "private_to_public_tftp_request_reply_pair", "rule"),
                new DetectionEvidenceItem("outcome", "outbound_tftp_exchange_shape_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Low,
                "Private-client TFTP request and public-server transfer reply observed; file identity, upload direction, completion, and exfiltration are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 2,
                windowSeconds: 30);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
