// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R137_PasswordResetOrEnrollmentSpikeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R137_PasswordResetOrEnrollmentSpikeRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private readonly NetworkBatch126130Window _observations = new();
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
            if (!NetworkBatch136140Evidence.RecoverySubmission(record, out var enrollment))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 300, 60, 3600));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 8, 3, 200);
            var routeKey = NetworkBatch131135Evidence.Fingerprint(HttpPath(record));
            var key = $"{Rule.RuleId}:{record.Source}:{BestHost(record)}:{routeKey}";
            var count = _observations.Add(key, record.Id, string.Empty, false, context.TimestampUtc, window).Count;
            if (count < threshold)
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", enrollment
                    ? "recovery_submission_burst,threshold_reached,enrollment_route"
                    : "recovery_submission_burst,threshold_reached", "rule"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("http.path", "[recovery-endpoint]", "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "Independent HTTP recovery or enrollment submissions accumulated within a bounded window.",
                "Severity is Medium because repeated account recovery submissions can indicate abuse or broken automation.",
                "Helpdesk resets, MFA enrollment campaigns and approved migration tools may generate similar requests.",
                "Confirm the activity against an approved helpdesk or MFA rollout.",
                "Correlate actual identity outcomes before treating requests as successful changes."));

            return MatchIdentityAccess(
                context,
                SeverityLevel.Medium,
                "Password reset or enrollment submission burst observed",
                "ResetEnrollmentBurst",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "attributed-recovery-submission");
                    confidence.AddEvidence(0.20, "threshold-reached");
                    if (enrollment) confidence.AddCorrelation(0.08, "enrollment-route");
                },
                count,
                window,
                $"{record.Source}:{BestHost(record)}:{routeKey}");
        }
    }
}
