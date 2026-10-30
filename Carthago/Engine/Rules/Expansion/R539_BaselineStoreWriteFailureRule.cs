// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R539_BaselineStoreWriteFailureRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R539_BaselineStoreWriteFailureRule : PlatformHealthAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R539", "Baseline Store Write Failure", "PlatformHealthAdvanced",
            "Detects concrete baseline persistence/write failures reported by the baseline subsystem.", SeverityLevel.High, "Rules.R539.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreatePlatformHealthProfile("R539", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert,
            new[] { RuleTelemetryKind.Baseline, RuleTelemetryKind.Flow }, new[] { "platform_health_event", "baseline_store", "write_failure" },
            new[] { "platform.component", "matched_conditions" },
            new[] { "The event must reference baseline store/persistence.", "The event must include write/save/commit failure semantics." },
            new[] { "Do not alert on read misses or first-seen baseline cold starts.", "Do not alert on generic database errors unrelated to baseline state." },
            88, 1, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(20), "baseline-store",
            new[] { "Read-only demo mode or intentionally disabled baseline persistence can be benign if explicitly configured." },
            new[] { "Mode", "CooldownSeconds", "BaselinePersistenceEnabled" },
            new[] { "positive baseline write failure", "negative baseline cold start" });
        public R539_BaselineStoreWriteFailureRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // GA R531-R540 — SOURCE CANDIDATE — UNVERIFIED.
            // Mutable packet text is not authenticated platform-health evidence.
            // Fail closed before counters, cooldowns or event construction.
            var missingProducer = PlatformHealthProducerEvidenceBoundary.GetMissingProducer(Descriptor.RuleId);
            if (missingProducer is { } missing)
                return RuleEvaluationResult.NoMatch(Descriptor.RuleId,
                    RuleNoMatchReasonCategory.InsufficientEvidence, missing.Code, missing.Detail);

            var r = context.Record; var text = Text(r);
            if (!IsPlatformHealthRecord(r) || !ContainsAny(text, "baseline")) return NoMatch();
            if (!ContainsAny(text, "write failed", "write failure", "save failed", "persist failed", "persistence failed", "commit failed", "store write")) return NoMatch();
            if (ContainsAny(text, "cold start", "first seen", "read miss", "not found")) return NoMatch();
            var e = new List<DetectionEvidenceItem> { new("matched_conditions", "platform_health,baseline_store,write_failure", "rule") };
            e.AddRange(AnalystContext("The baseline subsystem reported a write/persistence failure.", "Severity is High because baseline drift, novelty checks, and anomaly scoring become unreliable when state cannot be stored.", "Read-only demo mode may be expected if configured deliberately.", "Check baseline store permissions, disk availability, and serialization errors.", "Validate that new baselines are durable across restart."));
            return MatchPlatformHealth(context, SeverityLevel.High, "Baseline store write failure reported", "BaselineStoreWriteFailure", e,
                c => { c.AddEvidence(0.34, "platform-health-anchor"); c.AddEvidence(0.30, "baseline-store-context"); c.AddEvidence(0.26, "write-failure-semantics"); }, cooldownKey: MetricKey(r));
        }
    }
}
