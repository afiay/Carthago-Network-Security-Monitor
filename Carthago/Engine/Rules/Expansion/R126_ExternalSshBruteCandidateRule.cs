// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R126_ExternalSshBruteCandidateRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R126_ExternalSshBruteCandidateRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R126",
            Name: "External SSH Brute Candidate",
            Category: "IdentityAccess",
            Description: "Detects repeated SSH authentication failures across a boundary with thresholded evidence, rather than any SSH mention.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R126.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R126",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Identity, RuleTelemetryKind.Authentication },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port", "identity_context" },
            evidenceFields: new[] { "matched_conditions", "count", "ssh.distinctUsers" },
            positiveConditions: new[]
            {
                "The record must contain SSH context and explicit authentication failure evidence.",
                "The SSH failures must cross an internal-external boundary.",
                "A burst threshold must be reached before the rule alerts."
            },
            negativeConditions: new[]
            {
                "Do not alert on successful SSH sessions.",
                "Do not alert on isolated or low-volume SSH failures."
            },
            minimumConfidence: 78,
            threshold: 8,
            window: TimeSpan.FromMinutes(2),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Aggressive but approved vulnerability scanning or password-rotation testing can match."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive ssh failure burst sample",
                "negative successful ssh sample"
            });

        public R126_ExternalSshBruteCandidateRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsSshContext(record))
                return NoMatch();

            if (!IsCrossBoundary(record, out var outboundToExternal, out var inboundFromExternal))
                return NoMatch();

            if (!HasAuthFailureContext(record))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 120, 30, 1800));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 8, 4, 200);
            var windowKey = $"{Rule.RuleId}:{record.Source}:{record.Destination}";
            var count = CountWindowEvents(windowKey, context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var identity = ExtractIdentity(record);
            var distinctUsers = string.IsNullOrWhiteSpace(identity)
                ? 0
                : CountDistinctValues(windowKey + ":identity", identity, context.TimestampUtc, window);

            var matchedConditions = new List<string> { "ssh_failure_burst", "cross_boundary" };
            if (distinctUsers > 0) matchedConditions.Add("distinct_identities");
            if (outboundToExternal) matchedConditions.Add("outbound_to_external");
            if (inboundFromExternal) matchedConditions.Add("inbound_from_external");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("ssh.distinctUsers", distinctUsers.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "SSH authentication failures crossed a trust boundary and accumulated into a burst.",
                "Severity is High because repeated cross-boundary SSH failures are consistent with brute-force or credential-spraying attempts.",
                "Approved scanner activity, red-team validation, or planned password testing can match. Confirm whether the source is sanctioned.",
                "Validate whether the source is an approved scanner or automation host.",
                "Inspect the destination for successful SSH logins, new keys, or process launches after the failure burst."));

            return MatchIdentityAccess(
                context,
                SeverityLevel.High,
                "Cross-boundary SSH failure burst observed",
                "SshBrute",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.32, "ssh-context");
                    confidence.AddEvidence(0.20, "auth-failure-context");
                    confidence.AddEvidence(0.18, "threshold-reached");
                    if (outboundToExternal || inboundFromExternal) confidence.AddEvidence(0.16, "boundary-crossing");
                    if (distinctUsers >= 3) confidence.AddCorrelation(0.10, "multiple-identities");
                },
                count,
                window,
                $"{record.Source}:{record.Destination}:{record.DestinationPort}");
        }
    }
}
