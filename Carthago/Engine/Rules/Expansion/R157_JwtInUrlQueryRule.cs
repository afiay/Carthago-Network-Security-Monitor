// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R157_JwtInUrlQueryRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R157_JwtInUrlQueryRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R157",
            Name: "JWT In URL Query",
            Category: "HttpApi",
            Description: "Detects JWT-like bearer material exposed in URL query parameters instead of broad token substring matching.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R157.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R157",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "matched_conditions", "query.parameter" },
            positiveConditions: new[]
            {
                "The request URI must include a query parameter carrying a JWT-like token.",
                "The token should resemble a structured JWT rather than an opaque code or session identifier.",
                "Ordinary OIDC code/state callbacks without JWT material should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on opaque query tokens that are not JWTs.",
                "Do not alert on OAuth code or state parameters."
            },
            minimumConfidence: 74,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host",
            falsePositives: new[]
            {
                "Some legacy implicit-flow applications place id_token or access_token values in URLs; confirm whether this behavior is sanctioned."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive jwt query parameter sample",
                "negative opaque query token sample"
            });

        public R157_JwtInUrlQueryRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !TryGetJwtQueryParameter(record, out var parameterName))
                return NoMatch();

            var matchedConditions = new List<string> { "jwt_query_parameter", "structured_jwt" };
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("query.parameter", parameterName, "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "A URL query parameter carried JWT-like bearer material.",
                "Severity is Medium because JWTs in URLs leak into logs, browser history, and referrer chains much more easily than header-based tokens.",
                "Some older OAuth or implicit-flow integrations still surface id_token values in URLs. Validate whether the application is expected to do this.",
                "Review web server logs, browser telemetry, and referrer propagation risk for the affected application.",
                "Confirm whether the application should move the token to Authorization headers or secure POST bodies."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "JWT material exposed in URL query",
                "JwtInQuery",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "jwt-query-parameter");
                    confidence.AddEvidence(0.24, "structured-jwt");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{parameterName}");
        }
    }
}
