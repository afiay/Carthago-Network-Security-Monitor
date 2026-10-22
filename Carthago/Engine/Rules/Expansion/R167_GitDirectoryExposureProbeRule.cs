// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R167_GitDirectoryExposureProbeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R167_GitDirectoryExposureProbeRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R167",
            Name: "Git Directory Exposure Probe",
            Category: "HttpApi",
            Description: "Detects cross-boundary requests to exposed .git internals instead of broad git substring matches.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R167.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R167",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "matched_conditions", "http.path" },
            positiveConditions: new[]
            {
                "The flow must cross an internal/external boundary.",
                "The path must target exposed .git internals such as /.git/config or /.git/HEAD.",
                "Ordinary git website or repository browsing should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic git help or repository web paths.",
                "Do not alert without an exposed .git internal path."
            },
            minimumConfidence: 80,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+path",
            falsePositives: new[]
            {
                "Approved forensic or backup tooling may intentionally retrieve exposed repository internals in lab or recovery workflows."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive exposed git path sample",
                "negative repository web path sample"
            });

        public R167_GitDirectoryExposureProbeRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !HasMethod(record, "GET", "HEAD") || !IsGitExposurePath(record))
                return NoMatch();

            if (!IsCrossBoundary(record, out _, out _))
                return NoMatch();

            var path = HttpPath(record);
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "git_internal_path,boundary_crossing", "rule"),
                new("http.path", string.IsNullOrWhiteSpace(path) ? "/" : path, "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "A cross-boundary request targeted exposed .git internals.",
                "Severity is High because .git contents can leak source code, credentials, deployment secrets, and commit history.",
                "Rare recovery or forensic workflows may intentionally retrieve these files. Validate the target and source before escalating.",
                "Confirm whether the target should expose any .git directory content over HTTP.",
                "Review for adjacent .env, backup archive, and admin-path probes from the same source."));

            return MatchHttpApi(
                context,
                SeverityLevel.High,
                "Exposed .git directory path requested",
                "GitExposureProbe",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.32, "git-internal-path");
                    confidence.AddEvidence(0.18, "boundary-crossing");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{path}");
        }
    }
}
