// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R206_GitCloneFromUnknownExternalHostRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R206_GitCloneFromUnknownExternalHostRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R206",
            Name: "Git Clone From Unknown External Host",
            Category: "CloudDev",
            Description: "Detects smart-HTTP Git clone traffic to first-seen non-official external hosts instead of any git-upload-pack text.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R206.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R206",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.DevOpsAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "http.path", "baseline.reason", "matched_conditions" },
            positiveConditions: new[]
            {
                "The request must be a concrete Git smart-HTTP clone or fetch operation.",
                "The host must be external and not an official public Git provider.",
                "The host should be newly observed for the source to reduce noise from established enterprise Git infrastructure."
            },
            negativeConditions: new[]
            {
                "Do not alert on official GitHub, GitLab, or Bitbucket hosts.",
                "Do not alert on ordinary browser navigation to Git web pages."
            },
            minimumConfidence: 76,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+host",
            falsePositives: new[] { "Newly introduced enterprise Git servers or approved external mirrors can trigger this pattern during onboarding." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive unknown git clone host sample", "negative github clone sample" });

        public R206_GitCloneFromUnknownExternalHostRule() : base(Rule, Profile) { }

        private readonly NetworkBatch201205Window _observations = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            if (!NetworkBatch206215Evidence.Git(record, false)
                || !_observations.Observe(record, $"{Descriptor.RuleId}:{record.Source}:{host}", host,
                    context.TimestampUtc, TimeSpan.FromMinutes(15), 0, out _, out _))
                return NoMatch();

            var baseline = ObserveBaseline("clouddev.git-clone-host", record.Source ?? "unknown", host, context, "git=clone");
            var firstSeen = baseline.IsFirstSeen || FirstTimeSeen($"{record.Source}:gitclone:{host}", context.TimestampUtc);
            if (!firstSeen)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("baseline.reason", baseline.Reason, "baseline"),
                new("matched_conditions", "git_clone_smart_http,external_host,unofficial_git_host,first_seen", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The source performed a concrete Git clone or fetch against a first-seen non-official external host.",
                "Severity is Medium because unfamiliar external Git mirrors can indicate unsanctioned code retrieval or shadow dependency sources.",
                "Approved self-hosted mirrors or newly onboarded enterprise Git services can look similar. Validate ownership and developer workflow before escalating.",
                "Review the repository path and calling process for the clone request.",
                "Confirm whether the external Git host is approved for the environment."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "Git clone from first-seen external host observed",
                "GitCloneUnknownHost",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.20, "git-clone-smart-http");
                    confidence.AddEvidence(0.18, "unofficial-git-host");
                    confidence.AddEvidence(0.16, "first-seen-host");
                },
                cooldownKey: $"{record.Source}:{host}");
        }
    }
}
