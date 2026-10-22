// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R544_ExcessiveSuppressionRatioRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R544_ExcessiveSuppressionRatioRule : PlatformHealthAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R544", "Excessive Suppression Ratio", "PlatformHealthAdvanced",
            "Detects explicit rule-engine telemetry showing that suppression ratio exceeded an expected threshold for a rule or scope.", SeverityLevel.Medium, "Rules.R544.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreatePlatformHealthProfile("R544", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert,
            new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Baseline }, new[] { "platform_health_event", "suppression", "ratio_signal" },
            new[] { "rule.id", "matched_conditions" },
            new[] { "The event must reference suppression ratio/rate/budget.", "The event must indicate excessive/high/above-threshold suppression." },
            new[] { "Do not alert on one suppressed event.", "Do not alert on intentionally broad maintenance suppressions with an active expiry." },
            82, 1, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(30), "rule",
            new[] { "Temporary maintenance suppressions can raise ratios if the expiry and change record are correct." },
            new[] { "Mode", "CooldownSeconds", "SuppressionRatioThreshold" },
            new[] { "positive excessive suppression ratio", "negative single cooldown suppression" });
        public R544_ExcessiveSuppressionRatioRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record; var text = Text(r);
            if (!IsPlatformHealthRecord(r) || !ContainsAny(text, "suppression", "suppressed")) return NoMatch();
            if (!ContainsAny(text, "ratio", "rate", "budget", "excessive", "above threshold", "too high", "suppression storm")) return NoMatch();
            if (ContainsAny(text, "maintenance suppression active", "approved suppression", "expected suppression")) return NoMatch();
            var ruleKey = RuleKey(r);
            var e = new List<DetectionEvidenceItem> { new("rule.id", ruleKey, "rule-engine"), new("matched_conditions", "platform_health,suppression_ratio,excessive", "rule") };
            e.AddRange(AnalystContext("Rule-engine telemetry reported that suppression ratio is excessive for a rule or scope.", "Severity is Medium because overly broad suppression can hide real detections without breaking the pipeline.", "Short maintenance suppressions can be legitimate if scoped, approved, and expiring.", "Review active suppression predicates and expiry dates.", "Check whether the affected rule should be retuned instead of broadly suppressed."));
            return MatchPlatformHealth(context, SeverityLevel.Medium, "Excessive suppression ratio reported", "ExcessiveSuppressionRatio", e,
                c => { c.AddEvidence(0.32, "platform-health-anchor"); c.AddEvidence(0.28, "suppression-context"); c.AddEvidence(0.24, "excessive-ratio-signal"); if (ruleKey != "unknown-rule") c.AddEvidence(0.10, "rule-identity"); }, cooldownKey: ruleKey);
        }
    }
}
