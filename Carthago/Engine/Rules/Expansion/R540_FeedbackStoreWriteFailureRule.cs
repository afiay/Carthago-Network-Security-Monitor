// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R540_FeedbackStoreWriteFailureRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R540_FeedbackStoreWriteFailureRule : PlatformHealthAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R540", "Feedback Store Write Failure", "PlatformHealthAdvanced",
            "Detects concrete analyst-feedback persistence/write failures reported by the feedback subsystem.", SeverityLevel.Medium, "Rules.R540.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreatePlatformHealthProfile("R540", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert,
            new[] { RuleTelemetryKind.Flow }, new[] { "platform_health_event", "feedback_store", "write_failure" },
            new[] { "platform.component", "matched_conditions" },
            new[] { "The event must reference feedback store/persistence.", "The event must include write/save/commit failure semantics." },
            new[] { "Do not alert on user cancellation or validation errors before persistence.", "Do not alert on baseline-store failures; those are R539." },
            84, 1, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(20), "feedback-store",
            new[] { "Read-only demo mode can be benign when configured deliberately." },
            new[] { "Mode", "CooldownSeconds", "FeedbackPersistenceEnabled" },
            new[] { "positive feedback write failure", "negative user canceled feedback" });
        public R540_FeedbackStoreWriteFailureRule() : base(Rule, Profile) { }
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
            if (!IsPlatformHealthRecord(r) || !ContainsAny(text, "feedback")) return NoMatch();
            if (!ContainsAny(text, "write failed", "write failure", "save failed", "persist failed", "persistence failed", "commit failed", "store write")) return NoMatch();
            if (ContainsAny(text, "cancel", "validation", "invalid input")) return NoMatch();
            var e = new List<DetectionEvidenceItem> { new("matched_conditions", "platform_health,feedback_store,write_failure", "rule") };
            e.AddRange(AnalystContext("The feedback subsystem reported a write/persistence failure.", "Severity is Medium because analyst labels and tuning feedback may be lost, reducing future precision.", "Read-only demo mode may be expected if configured deliberately.", "Check feedback store permissions and serialization errors.", "Verify that analyst feedback survives application restart."));
            return MatchPlatformHealth(context, SeverityLevel.Medium, "Feedback store write failure reported", "FeedbackStoreWriteFailure", e,
                c => { c.AddEvidence(0.34, "platform-health-anchor"); c.AddEvidence(0.30, "feedback-store-context"); c.AddEvidence(0.24, "write-failure-semantics"); }, cooldownKey: MetricKey(r));
        }
    }
}
