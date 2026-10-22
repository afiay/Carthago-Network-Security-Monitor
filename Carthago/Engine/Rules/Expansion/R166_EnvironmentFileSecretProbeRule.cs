// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R166_EnvironmentFileSecretProbeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R166_EnvironmentFileSecretProbeRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R166",
            Name: "Environment File Secret Probe",
            Category: "HttpApi",
            Description: "Detects cross-boundary requests to concrete environment or secret-bearing file paths instead of broad config.json matching.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R166.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R166",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "matched_conditions", "http.path" },
            positiveConditions: new[]
            {
                "The flow must cross an internal/external boundary.",
                "The path must target a concrete environment or secret-bearing file such as /.env or /.aws/credentials.",
                "Generic web paths and ordinary config assets should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on non-secret asset requests.",
                "Do not alert without a concrete secret-file path."
            },
            minimumConfidence: 78,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+path",
            falsePositives: new[]
            {
                "Approved support or deployment tooling may intentionally retrieve environment files in isolated lab environments."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive env file path sample",
                "negative ordinary well-known path sample"
            });

        public R166_EnvironmentFileSecretProbeRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !HasMethod(record, "GET", "HEAD") || !IsEnvironmentFileProbe(record))
                return NoMatch();

            if (!IsCrossBoundary(record, out _, out _))
                return NoMatch();

            var path = HttpPath(record);
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "environment_secret_path,boundary_crossing", "rule"),
                new("http.path", string.IsNullOrWhiteSpace(path) ? "/" : path, "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "A cross-boundary request targeted a file path commonly used to store environment secrets or credentials.",
                "Severity is High because these files often expose database credentials, API keys, or cloud access material directly.",
                "Some isolated maintenance workflows may access these files intentionally. Validate whether the request came from an approved management source.",
                "Confirm whether the secret-bearing file should exist or be web-accessible on the target host.",
                "Review for adjacent .git, backup, phpinfo, or admin API probes from the same source."));

            return MatchHttpApi(
                context,
                SeverityLevel.High,
                "Secret-bearing environment file path requested",
                "EnvironmentFileProbe",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "secret-file-path");
                    confidence.AddEvidence(0.18, "boundary-crossing");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{path}");
        }
    }
}
