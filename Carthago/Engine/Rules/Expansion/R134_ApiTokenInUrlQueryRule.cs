// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R134_ApiTokenInUrlQueryRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R134_ApiTokenInUrlQueryRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R134",
            Name: "API Token In URL Query",
            Category: "IdentityAccess",
            Description: "Detects strong API-token-like query parameters with opaque values in request URIs, suppressing benign state and csrf parameters.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R134.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R134",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "matched_conditions", "http.path", "token.parameter" },
            positiveConditions: new[]
            {
                "The request URI must contain a strong token-like query parameter.",
                "The token value must look opaque enough to represent secret material.",
                "Benign state, nonce, csrf, and pagination parameters should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on csrf, state, or nonce parameters.",
                "Do not alert on short or obviously non-secret token placeholders."
            },
            minimumConfidence: 86,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+path",
            falsePositives: new[]
            {
                "Some legacy integrations still place tokens in URLs. Validate whether the pattern is expected and whether a header-based alternative exists."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive api token query sample",
                "negative csrf query sample"
            });

        public R134_ApiTokenInUrlQueryRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !TryGetSensitiveQueryParameter(record, out var parameterName, out var parameterValue))
                return NoMatch();

            var path = HttpPath(record);
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "sensitive_query_parameter,opaque_token_value", "rule"),
                new("http.path", string.IsNullOrWhiteSpace(path) ? "/" : path, "http"),
                new("token.parameter", parameterName, "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "A sensitive token-like parameter was placed in the request query string.",
                "Severity is High because URL query strings are widely logged, cached, and leaked through referrers.",
                "Legacy integrations may still embed tokens in URLs. Validate whether the token is expected and whether a header-based flow is available.",
                "Identify the system that generated the URL and whether the token is still valid.",
                "Check logs, proxies, and referrer chains for broader exposure of the same token."));

            return MatchIdentityAccess(
                context,
                SeverityLevel.High,
                "Sensitive API token found in URL query",
                "TokenInQuery",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.36, "http-query-parameter");
                    confidence.AddEvidence(0.28, "sensitive-parameter-name");
                    if (!string.IsNullOrWhiteSpace(parameterValue)) confidence.AddCorrelation(0.10, "opaque-token-value");
                },
                cooldownKey: $"{BestHost(record)}:{path}:{parameterName}");
        }
    }
}
