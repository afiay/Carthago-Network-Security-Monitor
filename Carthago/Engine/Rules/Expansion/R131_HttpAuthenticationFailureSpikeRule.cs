// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R131_HttpAuthenticationFailureSpikeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R131_HttpAuthenticationFailureSpikeRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R131",
            Name: "HTTP Authentication Failure Spike",
            Category: "IdentityAccess",
            Description: "Detects thresholded spikes of HTTP authentication failures with real auth context, instead of generic 403 noise.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R131.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R131",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Identity, RuleTelemetryKind.Authentication, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "identity_context" },
            evidenceFields: new[] { "matched_conditions", "count" },
            positiveConditions: new[]
            {
                "The record must contain explicit HTTP authentication failure evidence.",
                "The failures must carry authentication context rather than generic authorization noise.",
                "A burst threshold must be reached before the rule alerts."
            },
            negativeConditions: new[]
            {
                "Do not alert on low-volume failures.",
                "Do not alert on generic 403 pages with no authentication context."
            },
            minimumConfidence: 72,
            threshold: 15,
            window: TimeSpan.FromMinutes(5),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Broken API clients, expired credentials during deployments, or sanctioned test harnesses can match."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive auth failure spike sample",
                "negative generic forbidden sample"
            });

        public R131_HttpAuthenticationFailureSpikeRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !HasAuthFailureContext(record) || !(HasAuthHeaderContext(record) || HasLoginContext(record)))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 300, 60, 3600));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 15, 5, 500);
            var path = HttpPath(record);
            var key = $"{Rule.RuleId}:{record.Source}:{BestHost(record)}:{path}";
            var count = CountWindowEvents(key, context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var matchedConditions = new List<string> { "http_auth_failure_burst", "threshold_reached" };
            if (HasAuthHeaderContext(record)) matchedConditions.Add("auth_header_context");
            if (HasLoginContext(record)) matchedConditions.Add("login_path_context");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("http.path", string.IsNullOrWhiteSpace(path) ? "/" : path, "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "HTTP authentication failures accumulated quickly against the same path or destination with real auth context.",
                "Severity is Medium because this pattern can indicate repeated credential abuse, broken secrets, or failing auth integrations.",
                "Broken API clients, expired credentials, or integration outages can look similar. Validate whether the source is a sanctioned client or automation job.",
                "Confirm whether the failures come from a known client, service account, or test harness.",
                "Inspect for any successful follow-on authentication after the failure spike."));

            return MatchIdentityAccess(
                context,
                SeverityLevel.Medium,
                "HTTP authentication failure spike observed",
                "HttpAuthFailures",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.26, "auth-failure-context");
                    confidence.AddEvidence(0.20, "threshold-reached");
                    if (HasAuthHeaderContext(record)) confidence.AddEvidence(0.16, "auth-header-context");
                    if (HasLoginContext(record)) confidence.AddCorrelation(0.10, "login-path-context");
                },
                count,
                window,
                $"{record.Source}:{BestHost(record)}:{path}");
        }
    }
}
