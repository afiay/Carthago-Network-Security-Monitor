// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R205_CiCdSecretTokenInUrlRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R205_CiCdSecretTokenInUrlRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R205",
            Name: "CI CD Secret Token In URL",
            Category: "CloudDev",
            Description: "Detects concrete CI/CD secret token parameters embedded in URL query strings instead of broad pipeline keyword matches.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R205.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R205",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Payload, RuleTelemetryKind.DevOpsAudit },
            requiredFields: new[] { "source", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "http.path", "matched_conditions" },
            positiveConditions: new[]
            {
                "The URL query string must contain a concrete CI/CD token parameter name.",
                "The parameter value should look like a real token rather than a placeholder."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic build-system words without a URL token parameter.",
                "Do not alert on short placeholder values."
            },
            minimumConfidence: 86,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+query",
            falsePositives: new[] { "Some lab traffic may intentionally demonstrate CI token leakage patterns for training or testing." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive ci token in url sample", "negative ci docs sample" });

        public R205_CiCdSecretTokenInUrlRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!NetworkBatch201205Evidence.CiSecret(context.Record, out var parameterName))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("query.parameter", parameterName, "http"),
                new("matched_conditions", "cicd_secret_query_parameter,token_like_value", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The URL contained a concrete CI/CD secret token parameter with a value that looked like a real credential.",
                "Severity is High because secret-bearing URLs can leak pipeline credentials through proxies, logs, and browser history.",
                "Some lab or training environments intentionally generate leaked-token examples. Validate whether the traffic is synthetic before escalating.",
                "Rotate the exposed token if it is real and review downstream logs for additional exposure.",
                "Confirm whether the destination service received a privileged pipeline credential."));

            return MatchHttpApi(
                context,
                SeverityLevel.High,
                "CI/CD secret token exposed in URL",
                "CiCdSecretInUrl",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "cicd-secret-query-parameter");
                    confidence.AddEvidence(0.18, "token-like-value");
                },
                cooldownKey: $"{context.Record.Source}:{parameterName}:{NetworkBatch166170Evidence.Key(context.Record.HttpUri ?? "")}");
        }
    }
}
