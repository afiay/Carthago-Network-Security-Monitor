// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R272_MultiSignalRuleStackSurgeFromHostRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R272_MultiSignalRuleStackSurgeFromHostRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R272",
            Name: "Multi-Signal Rule Stack Surge From Host",
            Category: "EvasionInfra",
            Description: "Detects multi-signal rule stack surge from host only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R272.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R272",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_process_or_info" },
            evidenceFields: new[] { "network.source", "network.destination", "process.name", "event.info", "matched_conditions" },
            positiveConditions: new[]
            {
                "Requires distinct emitted rule-engine events with rule IDs, family, host, timestamp and provenance.",
                "Uses only engine-owned post-policy emitted detections for the source host.",
                "Requires at least three distinct rules and three distinct detection families."
            },
            negativeConditions: new[]
            {
                "Do not alert when the required telemetry fields are absent.",
                "Do not alert on generic logs that mention the concept but lack network/process/pipeline evidence."
            },
            minimumConfidence: 82,
            threshold: 3,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+destination+behavior",
            falsePositives: new[] { "Demo mode, replay tests, and synthetic validation runs can intentionally create multi-signal surges." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R272 evidence-gated sample", "negative R272 descriptor-only sample", "negative R272 missing telemetry sample" });

        public R272_MultiSignalRuleStackSurgeFromHostRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var signals = Carthago.Services.RuleEngine.SnapshotR272Signals(
                context.Record.Source, context.TimestampUtc);
            var families = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var rules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var signal in signals)
            {
                if (signal.RuleId == "R272") continue;
                rules.Add(signal.RuleId);
                families.Add(signal.Family);
            }
            if (rules.Count < 3 || families.Count < 3)
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                    "R272_INDEPENDENT_SIGNALS_REQUIRED",
                    "Three distinct emitted rules and detection families are required.");

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "engine_emitted_signals,distinct_rules,distinct_families", "rule"),
                new("rule.signalCount", rules.Count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("rule.familyCount", families.Count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule")
            };
            return MatchEvasionInfra(context, SeverityLevel.High, "Independent rule detections from one source",
                "RuleStackSurge", evidence,
                c => { c.AddEvidence(0.40, "engine-emission"); c.AddEvidence(0.30, "distinct-families"); c.AddEvidence(0.20, "host-window"); },
                count: rules.Count, window: Profile.Window, cooldownKey: context.Record.Source + ":rule-stack");
        }
    }
}
