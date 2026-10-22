// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R169_AdminLoginBruteIndicatorRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R169_AdminLoginBruteIndicatorRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R169",
            Name: "Admin Login Brute Indicator",
            Category: "HttpApi",
            Description: "Detects repeated authentication failures against admin login paths instead of every admin page request.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R169.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R169",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Authentication },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "matched_conditions", "count", "http.path" },
            positiveConditions: new[]
            {
                "The request must target an admin login path with authentication failure context.",
                "The same source must repeat failures to the same admin login surface within the configured window.",
                "Isolated admin page views or successful logins should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on one-off admin login visits.",
                "Do not alert on successful admin authentication without failure context."
            },
            minimumConfidence: 74,
            threshold: 6,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+host+path",
            falsePositives: new[]
            {
                "Password resets, legitimate admins with stale credentials, and sanctioned brute-force tests can resemble this pattern."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive repeated admin login failures sample",
                "negative successful admin login sample"
            });

        public R169_AdminLoginBruteIndicatorRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !IsAdminLoginPath(record) || !HasAuthFailureContext(record))
                return NoMatch();

            if (!IsCrossBoundary(record, out _, out _))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 600, 120, 7200));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 6, 3, 100);
            var path = HttpPath(record);
            var count = CountWindowEvents($"{Rule.RuleId}:{record.Source}:{BestHost(record)}:{path}", context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "admin_login_path,auth_failure_context,threshold_reached", "rule"),
                new("http.path", string.IsNullOrWhiteSpace(path) ? "/" : path, "http"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "A source repeatedly failed against an admin login path in a short window.",
                "Severity is Medium because concentrated admin login failures often indicate password spraying or brute forcing against privileged interfaces.",
                "Legitimate admins with expired credentials or sanctioned password testing can trigger this rule.",
                "Confirm whether the source belongs to an approved administrative user, test harness, or password rotation workflow.",
                "Review adjacent admin panel, CORS preflight, upload, or request smuggling activity from the same source."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "Repeated admin login failures observed",
                "AdminLoginBrute",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.20, "admin-login-path");
                    confidence.AddEvidence(0.24, "auth-failure-context");
                    confidence.AddEvidence(0.18, "threshold-reached");
                },
                count,
                window,
                $"{record.Source}:{BestHost(record)}:{path}");
        }
    }
}
