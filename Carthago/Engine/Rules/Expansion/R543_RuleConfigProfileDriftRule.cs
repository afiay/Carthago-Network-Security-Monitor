// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R543_RuleConfigProfileDriftRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R543_RuleConfigProfileDriftRule : PlatformHealthAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R543", "Rule Config Profile Drift", "PlatformHealthAdvanced",
            "Detects explicit drift between expected rule precision/config profile and the active runtime profile.", SeverityLevel.Medium, "Rules.R543.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreatePlatformHealthProfile("R543", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert,
            new[] { RuleTelemetryKind.Flow }, new[] { "platform_health_event", "rule_config", "drift_signal" },
            new[] { "rule.id", "matched_conditions" },
            new[] { "The event must reference rule configuration or precision-profile drift.", "The event must indicate mismatch between expected and active configuration." },
            new[] { "Do not alert on normal user tuning where the override is tracked.", "Do not alert on documented environment-specific profiles." },
            82, 1, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(30), "rule",
            new[] { "Environment-specific profile overrides are legitimate when governed and auditable." },
            new[] { "Mode", "CooldownSeconds", "ApprovedProfileHash" },
            new[] { "positive unexpected profile hash drift", "negative tracked user override" });
        public R543_RuleConfigProfileDriftRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record; var text = Text(r);
            if (!IsPlatformHealthRecord(r) || !ContainsAny(text, "rule config", "rule profile", "precision profile", "profile drift", "configuration drift", "config drift")) return NoMatch();
            if (!ContainsAny(text, "drift", "mismatch", "unexpected", "hash mismatch", "untracked", "out of policy")) return NoMatch();
            if (ContainsAny(text, "approved override", "tracked override", "expected profile")) return NoMatch();
            var ruleKey = RuleKey(r);
            var e = new List<DetectionEvidenceItem> { new("rule.id", ruleKey, "rule-engine"), new("matched_conditions", "platform_health,rule_config,profile_drift", "rule") };
            e.AddRange(AnalystContext("The active rule configuration/profile differs from the expected governed profile.", "Severity is Medium because unexpected profile drift can silently change precision, severity, or runtime mode.", "Approved tenant or environment overrides can be legitimate.", "Compare expected and active profile hashes.", "Review recent settings changes, content-pack updates, and local overrides."));
            return MatchPlatformHealth(context, SeverityLevel.Medium, "Rule config profile drift reported", "RuleConfigProfileDrift", e,
                c => { c.AddEvidence(0.32, "platform-health-anchor"); c.AddEvidence(0.28, "rule-config-context"); c.AddEvidence(0.24, "drift-signal"); if (ruleKey != "unknown-rule") c.AddEvidence(0.10, "rule-identity"); }, cooldownKey: ruleKey);
        }
    }
}
