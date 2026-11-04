// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R2697.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R716_SiprotecDiagnosticUdpFanoutRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R716",
            Name: "SIPROTEC-shaped 18-byte UDP/50000 fanout to private devices",
            Category: "IotOtAdvanced",
            Description: "One source sends 18-byte UDP payloads to diagnostic port 50000 on two distinct private devices within 60 seconds. This is a narrow SIPROTEC/Industroyer-shaped packet pattern only; restart service semantics, device identity, authorization, offline state, and impact are unverified.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R716.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R716",
            Name = "SIPROTEC-shaped 18-byte UDP/50000 fanout to private devices",
            Category = "IotOtAdvanced",
            Description = "Workbook R2697: the source analytic correlates restart/reset semantics and device-offline alarms. Carthago does not possess those outcomes, so this candidate requires only the documented 18-byte UDP/50000 shape across two private targets.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "udp", "destination.port", "l4.length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet, parser, and best-effort process fields for this exact independent predicate.",
                "Multi-observation rules use bounded unique packet IDs with UTC ordering and a fixed rule-owned window.",
                "Only the observable network/request/process association is claimed; endpoint or server outcome is not inferred."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, and free-form Info-only indicators.",
                "Reject duplicate packet IDs, stale/out-of-order observations, and cooldown repeats.",
                "Do not infer authentication, command-line arguments, file reads/writes, transfer completion, exploit success, or compromise."
            },
            FalsePositives = new[] { "Authorized relay diagnostics, vendor maintenance, lab replay, vulnerability assessment, or non-SIPROTEC applications using UDP/50000 can resemble this packet shape." },
            MinimumConfidence = 84,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+two_distinct_private_udp50000_targets",
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
        private readonly Research706DistinctWindow _targets = new();

        public R716_SiprotecDiagnosticUdpFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research716Evidence.Udp18ToPrivateDiagnosticPort(r))
                return NoMatch();
            if (!_targets.Observe(r.Source + "|udp50000|18", r.Destination!, r.Id, context.TimestampUtc, 2, 60))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2697", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "udp50000_18byte_two_private_target_fanout", "rule"),
                new DetectionEvidenceItem("outcome", "siprotec_restart_shaped_packets_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Two private devices received 18-byte UDP/50000 packets from one source within one minute; restart semantics and device impact are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 2,
                windowSeconds: 60);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
