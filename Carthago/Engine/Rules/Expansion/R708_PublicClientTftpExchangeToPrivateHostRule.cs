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
            Description: "A public UDP client contacts a private host on TFTP/69 and the same private host replies from an ephemeral UDP port to the original client port within 30 seconds. This does not identify firmware-update mode, a device role, file name, transfer completion, or authorization.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R708.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R708",
            Name = "Public client TFTP request followed by private-host transfer reply",
            Category = "IotOtAdvanced",
            Description = "Workbook R2799: the workbook asserts firmware-update mode from unapproved engineering sources. Carthago cannot identify that mode or approved workstation lists, so only an inbound cross-boundary TFTP request/reply shape is implemented.",
            Severity = SeverityLevel.Medium,
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
        private readonly Research706TftpWindow _tftp = new();

        public R708_PublicClientTftpExchangeToPrivateHostRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research706Evidence.Udp(r)) return NoMatch();
            var request = Research706Evidence.PublicToPrivate(r) && r.DestinationPort == 69 && r.SourcePort is > 1024;
            var reply = Research706Evidence.PrivateToPublic(r) && r.SourcePort is > 1024 && r.DestinationPort is > 1024;
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
                new DetectionEvidenceItem("research.identifier", "workbook.R2799", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_to_private_tftp_request_reply_pair", "rule"),
                new DetectionEvidenceItem("outcome", "inbound_tftp_exchange_shape_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Public-client TFTP request and private-host transfer reply observed; firmware mode, file contents, and transfer success are unknown.",
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
