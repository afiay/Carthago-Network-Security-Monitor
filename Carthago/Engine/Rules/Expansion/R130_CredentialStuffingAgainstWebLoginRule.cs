// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R130_CredentialStuffingAgainstWebLoginRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R130_CredentialStuffingAgainstWebLoginRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private readonly NetworkBatch126130Window _observations = new();
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R130",
            Name: "Credential Stuffing Against Web Login",
            Category: "IdentityAccess",
            Description: "Detects thresholded bursts of login submissions with failures or many identities against the same web login path.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R130.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R130",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Identity, RuleTelemetryKind.Authentication, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "identity_context" },
            evidenceFields: new[] { "matched_conditions", "count", "web.distinctIdentities" },
            positiveConditions: new[]
            {
                "The request must target a web login path with credential submission semantics.",
                "A burst threshold must be met within a short window.",
                "The burst must carry authentication failures or multiple distinct identities."
            },
            negativeConditions: new[]
            {
                "Do not alert on low-volume login failures.",
                "Do not alert on generic browsing that merely mentions passwords or credentials."
            },
            minimumConfidence: 80,
            threshold: 20,
            window: TimeSpan.FromMinutes(5),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Load tests, auth regression testing, or approved password-audit tooling can match."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive login stuffing burst sample",
                "negative low volume login sample"
            });

        public R130_CredentialStuffingAgainstWebLoginRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch126130Evidence.WebLoginSubmission(record, HttpPath(record)))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 300, 60, 3600));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 20, 5, 500);
            var path = HttpPath(record);
            var key = $"{Rule.RuleId}:{record.Source}:{BestHost(record)}:web-login";
            var identity = ExtractIdentity(record);
            var failureContext = NetworkBatch126130Evidence.ExplicitWebFailure(record);
            if (!failureContext && string.IsNullOrWhiteSpace(identity))
                return NoMatch();
            var stats = _observations.Add(key, record.Id, identity, failureContext, context.TimestampUtc, window);
            var count = stats.Count;
            if (count < threshold)
                return NoMatch();
            var distinctIdentities = stats.Distinct;
            var failureBurst = stats.Failures >= threshold;
            if (!failureBurst && distinctIdentities < 5)
                return NoMatch();

            var matchedConditions = new List<string> { "login_submission_burst", "threshold_reached" };
            if (failureBurst) matchedConditions.Add("auth_failure_context");
            if (distinctIdentities >= 5) matchedConditions.Add("many_identities");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("web.distinctIdentities", distinctIdentities.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("http.path", "[web-login]", "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "A web login path received a burst of credential submissions with failure context or many distinct identities.",
                "Severity is High because this pattern is consistent with credential stuffing or password spraying against a web-facing login.",
                "Load testing, auth QA, or sanctioned password-audit tooling can match. Validate whether the source is approved.",
                "Confirm whether the source belongs to an approved scanner or load test.",
                "Inspect the targeted accounts for successful follow-on logins or MFA prompts."));

            return MatchIdentityAccess(
                context,
                SeverityLevel.High,
                "Credential stuffing-like web login burst observed",
                "CredentialStuffing",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "login-submission-context");
                    confidence.AddEvidence(0.22, "threshold-reached");
                    if (failureBurst) confidence.AddEvidence(0.18, "auth-failure-context");
                    if (distinctIdentities >= 5) confidence.AddCorrelation(0.16, "many-identities");
                },
                count,
                window,
                $"{record.Source}:{BestHost(record)}:web-login");
        }
    }
}
