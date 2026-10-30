// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R533_RuleMatchVolumeAnomalyRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R533_RuleMatchVolumeAnomalyRule : PlatformHealthAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R533",
            Name: "Rule Match Volume Anomaly",
            Category: "PlatformHealthAdvanced",
            Description: "Detects explicit rule-match volume anomalies emitted by the rule engine, requiring rule identity plus spike/surge/regression semantics.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R533.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreatePlatformHealthProfile(
            "R533", RulePrecisionMaturity.Validated, RuleRuntimeMode.Shadow,
            new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Baseline },
            new[] { "platform_health_event", "rule_identity", "volume_anomaly_signal" },
            new[] { "rule.id", "matched_conditions", "platform.windowCount" },
            new[] { "Explicit rule-engine telemetry must indicate match-volume anomaly, surge, or spike.", "A concrete rule identifier or rule metric should be present." },
            new[] { "Do not alert on a single ordinary rule match.", "Do not alert on generic high traffic volume without rule-engine context." },
            80, 1, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(20), "rule",
            new[] { "Load tests, replay tests, or enabling a new noisy rule can legitimately increase match volume." },
            new[] { "Mode", "CooldownSeconds", "ApprovedLoadTestWindow" },
            new[] { "positive rule match surge health event", "negative ordinary high traffic event" });

        public R533_RuleMatchVolumeAnomalyRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // GA R531-R540 — SOURCE CANDIDATE — UNVERIFIED.
            // Mutable packet text is not authenticated platform-health evidence.
            // Fail closed before counters, cooldowns or event construction.
            var missingProducer = PlatformHealthProducerEvidenceBoundary.GetMissingProducer(Descriptor.RuleId);
            if (missingProducer is { } missing)
                return RuleEvaluationResult.NoMatch(Descriptor.RuleId,
                    RuleNoMatchReasonCategory.InsufficientEvidence, missing.Code, missing.Detail);

            var record = context.Record;
            var text = Text(record);
            if (!IsPlatformHealthRecord(record) || !ContainsAny(text, "rule match", "match volume", "rule volume", "rule-engine volume", "detection volume"))
                return NoMatch();
            if (!ContainsAny(text, "anomaly", "spike", "surge", "zscore", "z-score", "baseline", "regression", "unexpected"))
                return NoMatch();

            var ruleKey = RuleKey(record);
            if (ruleKey == "unknown-rule" && !ContainsAny(text, "all rules", "catalog", "rule engine"))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("rule.id", ruleKey, "rule-engine"),
                new("matched_conditions", "platform_health,rule_match_volume,baseline_anomaly", "rule")
            };
            evidence.AddRange(AnalystContext(
                "Rule-engine telemetry reported an abnormal match-volume change for a concrete rule or catalog scope.",
                "Severity is Medium because this often indicates a noisy rule, telemetry replay, attack burst, or rule precision regression rather than a confirmed compromise by itself.",
                "Replay tests, demo mode, content-pack rollout, or intentionally broad hunting rules may increase volume.",
                "Identify the affected rule and compare recent match volume against deployment changes.",
                "Check whether a new content pack, parser change, or traffic replay was active."));

            return MatchPlatformHealth(context, SeverityLevel.Medium, "Rule match volume anomaly reported", "RuleMatchVolumeAnomaly", evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "platform-health-anchor");
                    confidence.AddEvidence(0.28, "rule-match-volume-context");
                    confidence.AddEvidence(0.24, "anomaly-baseline-signal");
                    if (ruleKey != "unknown-rule") confidence.AddEvidence(0.12, "rule-identity");
                }, cooldownKey: $"{RuleKey(record)}:{MetricKey(record)}");
        }
    }
}
