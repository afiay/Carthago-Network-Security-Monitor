// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R137_PasswordResetOrEnrollmentSpikeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R137_PasswordResetOrEnrollmentSpikeRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R137",
            Name: "Password Reset Or Enrollment Spike",
            Category: "IdentityAccess",
            Description: "Detects repeated password-reset or MFA-enrollment actions in a short window, rather than any mention of recovery text.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R137.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R137",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Identity, RuleTelemetryKind.Authentication, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "identity_context" },
            evidenceFields: new[] { "matched_conditions", "count", "http.path" },
            positiveConditions: new[]
            {
                "The request must indicate password reset, account recovery, or MFA enrollment activity.",
                "A short-window burst threshold must be reached.",
                "The activity must look action-oriented rather than a single page view."
            },
            negativeConditions: new[]
            {
                "Do not alert on isolated reset page views.",
                "Do not alert on low-volume or non-interactive browsing."
            },
            minimumConfidence: 72,
            threshold: 8,
            window: TimeSpan.FromMinutes(5),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Helpdesk campaigns, MFA migrations, or planned reset waves can match."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive reset or enrollment spike sample",
                "negative isolated reset page view sample"
            });

        public R137_PasswordResetOrEnrollmentSpikeRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasResetOrEnrollmentContext(record))
                return NoMatch();

            if (!UsesCredentialSubmissionMethod(record) && !ContainsAny(Text(record), "submit", "verify", "challenge", "recover account", "password reset"))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 300, 60, 3600));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 8, 3, 200);
            var path = HttpPath(record);
            var key = $"{Rule.RuleId}:{record.Source}:{BestHost(record)}:{path}";
            var count = CountWindowEvents(key, context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var matchedConditions = new List<string> { "reset_or_enrollment_burst", "threshold_reached" };
            if (ContainsAny(Text(record), "mfa", "totp", "webauthn")) matchedConditions.Add("mfa_or_enrollment_context");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("http.path", string.IsNullOrWhiteSpace(path) ? "/" : path, "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "Password reset or enrollment actions accumulated into a short-window burst.",
                "Severity is Medium because clustered recovery or enrollment activity can indicate account takeover preparation or spray-and-reset workflows.",
                "Helpdesk migrations, MFA campaigns, or user onboarding can match. Validate whether the burst aligns with an approved change window.",
                "Confirm whether the activity matches a sanctioned helpdesk or MFA rollout.",
                "Inspect the targeted accounts for successful logins, recovery completions, or MFA device changes."));

            return MatchIdentityAccess(
                context,
                SeverityLevel.Medium,
                "Password reset or enrollment burst observed",
                "ResetEnrollmentBurst",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "reset-enrollment-context");
                    confidence.AddEvidence(0.20, "threshold-reached");
                    if (ContainsAny(Text(record), "mfa", "totp", "webauthn")) confidence.AddCorrelation(0.08, "mfa-enrollment-context");
                },
                count,
                window,
                $"{record.Source}:{BestHost(record)}:{path}");
        }
    }
}
