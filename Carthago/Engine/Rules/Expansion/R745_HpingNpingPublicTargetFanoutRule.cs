// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R2591.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R745_HpingNpingPublicTargetFanoutRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R745",
            Name: "hping/nping rapid public-target SYN fanout",
            Category: "Network",
            Description: "hping3, hping, or nping produces TCP SYNs to four distinct public targets within ten seconds. Packet rate beyond the observed threshold, source spoofing, victim impact and denial-of-service outcome are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R745.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R745",
            Name = "hping/nping rapid public-target SYN fanout",
            Category = "Network",
            Description = "workbook.R2591: the source analytic identifies Linux flooding tools generating high-volume traffic. This candidate uses exact tool attribution plus rapid distinct-target SYN fanout, making it separate from R732's same-peer generic Linux burst.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "destination.port", "tcp.flags", "process.name", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet/parser fields and the exact local process/network predicate for this independent candidate.",
                "Correlated rules require unique packet IDs, monotonic UTC ordering and bounded rule-owned state.",
                "Only the observable request, TLS contact, connection attempt, packet burst or cadence is asserted."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, malformed endpoints and free-form Info-only evidence.",
                "Reject duplicate packet IDs, reverse time, expired windows and cooldown repeats.",
                "Do not infer file reads, command-line arguments, cron execution, upload completion, C2 control, proxy establishment, encoded content, DoS impact or compromise."
            },
            FalsePositives = new[] { "Authorized stress tests, network measurement, security assessments and lab exercises commonly use hping3 or nping across multiple targets." },
            MinimumConfidence = 84,
            WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(10),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+hping_nping_pid+four_public_targets",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive shaped observation and independent benign near miss",
                "missing and contradictory telemetry",
                "duplicate IDs, reverse time and window expiry where stateful",
                "cooldown suppression and recovery",
                "fixed evidence privacy, non-convergence, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _targets = new();

        public R745_HpingNpingPublicTargetFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research676Evidence.Syn(r)
                || !Research736Evidence.PrivateToPublic(r)
                || !Research736Evidence.FloodTool(r)
                || !_targets.Observe(r.Source + "|" + r.ProcessId,
                    r.Destination!, r.Id, context.TimestampUtc, 4, 10))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2591", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "hping_nping_four_distinct_public_syn_targets", "rule"),
                new DetectionEvidenceItem("outcome", "rapid_target_fanout_only_dos_impact_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "hping/nping rapid public-target SYN fanout observed; spoofing, packet-rate scale, victim impact and denial-of-service outcome are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 4,
                windowSeconds: 10);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
