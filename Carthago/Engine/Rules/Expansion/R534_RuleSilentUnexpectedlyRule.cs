// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R534_RuleSilentUnexpectedlyRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R534_RuleSilentUnexpectedlyRule : PlatformHealthAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R534", "Rule Silent Unexpectedly", "PlatformHealthAdvanced",
            "Detects explicit platform telemetry that a rule stopped matching despite expected telemetry/baseline activity; absence is accepted only from a health monitor, never inferred from one packet.",
            SeverityLevel.Medium, "Rules.R534.Enabled", true);

        private static readonly RulePrecisionProfile Profile = CreatePlatformHealthProfile(
            "R534", RulePrecisionMaturity.Validated, RuleRuntimeMode.Shadow,
            new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Baseline },
            new[] { "platform_health_event", "rule_identity", "silence_signal" },
            new[] { "rule.id", "matched_conditions" },
            new[] { "A rule-health monitor must explicitly report unexpected silence/no matches.", "The event should include the affected rule or catalog scope." },
            new[] { "Do not infer silence from ordinary traffic records.", "Do not alert when the rule is intentionally disabled, suppressed, or in maintenance." },
            78, 1, TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(30), "rule",
            new[] { "Low traffic periods, maintenance windows, disabled rules, or known suppressions can be legitimate." },
            new[] { "Mode", "CooldownSeconds", "MaintenanceWindow" },
            new[] { "positive explicit rule silent health event", "negative no traffic packet" });

        public R534_RuleSilentUnexpectedlyRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var text = Text(record);
            if (!IsPlatformHealthRecord(record) || !ContainsAny(text, "rule silent", "silent unexpectedly", "unexpected silence", "no matches", "stopped matching")) return NoMatch();
            if (ContainsAny(text, "disabled", "suppressed intentionally", "maintenance", "expected silence")) return NoMatch();
            var ruleKey = RuleKey(record);
            if (ruleKey == "unknown-rule" && !ContainsAny(text, "catalog", "rule group", "rule engine")) return NoMatch();

            var evidence = new List<DetectionEvidenceItem> { new("rule.id", ruleKey, "rule-engine"), new("matched_conditions", "platform_health,rule_silence,unexpected", "rule") };
            evidence.AddRange(AnalystContext("A rule-health monitor reported unexpected silence for a rule that normally receives matching telemetry.", "Severity is Medium because this may indicate parser drift, telemetry loss, rule misconfiguration, or excessive suppression.", "Quiet environments and planned maintenance can legitimately reduce matches.", "Check telemetry ingestion and parser field coverage for the affected rule.", "Verify the rule is enabled and not hidden behind a broad suppression."));

            return MatchPlatformHealth(context, SeverityLevel.Medium, "Rule became unexpectedly silent", "RuleSilentUnexpectedly", evidence,
                c => { c.AddEvidence(0.34, "platform-health-anchor"); c.AddEvidence(0.26, "rule-silence-signal"); c.AddEvidence(0.20, "unexpected-not-maintenance"); if (ruleKey != "unknown-rule") c.AddEvidence(0.12, "rule-identity"); },
                cooldownKey: ruleKey);
        }
    }
}
