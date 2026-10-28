// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R207_GitPushToUnknownExternalHostRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R207_GitPushToUnknownExternalHostRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R207",
            Name: "Git Push To Unknown External Host",
            Category: "CloudDev",
            Description: "Detects Git smart-HTTP push traffic to first-seen non-official external hosts instead of any git-receive-pack text.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R207.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R207",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.DevOpsAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "http.path", "baseline.reason", "matched_conditions" },
            positiveConditions: new[]
            {
                "The request must be a concrete Git smart-HTTP push operation.",
                "The host must be external and not an official public Git provider.",
                "The host should be newly observed for the source."
            },
            negativeConditions: new[]
            {
                "Do not alert on official GitHub, GitLab, or Bitbucket hosts.",
                "Do not alert on browser web navigation."
            },
            minimumConfidence: 82,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+host",
            falsePositives: new[] { "Approved self-hosted Git remotes or newly introduced mirrors can generate this pattern legitimately." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive unknown git push host sample", "negative gitlab push sample" });

        public R207_GitPushToUnknownExternalHostRule() : base(Rule, Profile) { }

        private readonly NetworkBatch201205Window _observations = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            if (!NetworkBatch206215Evidence.Git(record, true)
                || !_observations.Observe(record, $"{Descriptor.RuleId}:{record.Source}:{host}", host,
                    context.TimestampUtc, TimeSpan.FromMinutes(15), 0, out _, out _))
                return NoMatch();

            var baseline = ObserveBaseline("clouddev.git-push-host", record.Source ?? "unknown", host, context, "git=push");
            var firstSeen = baseline.IsFirstSeen || FirstTimeSeen($"{record.Source}:gitpush:{host}", context.TimestampUtc);
            if (!firstSeen)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("baseline.reason", baseline.Reason, "baseline"),
                new("matched_conditions", "git_push_smart_http,external_host,unofficial_git_host,first_seen", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The source performed a concrete Git push against a first-seen non-official external host.",
                "Severity is High because pushing code to an unfamiliar external Git remote can indicate source-code exfiltration or unsanctioned distribution of internal repositories.",
                "Approved self-hosted remotes or onboarding of new mirrors can look similar. Validate the remote owner and project context before escalating.",
                "Review the repository path and calling process for the push request.",
                "Confirm whether the remote Git host is approved for source publication."));

            return MatchHttpApi(
                context,
                SeverityLevel.High,
                "Git push to first-seen external host observed",
                "GitPushUnknownHost",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "git-push-smart-http");
                    confidence.AddEvidence(0.20, "unofficial-git-host");
                    confidence.AddEvidence(0.16, "first-seen-host");
                },
                cooldownKey: $"{record.Source}:{host}");
        }
    }
}
