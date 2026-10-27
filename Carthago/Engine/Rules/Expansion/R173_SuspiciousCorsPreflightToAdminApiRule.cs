// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R173_SuspiciousCorsPreflightToAdminApiRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R173_SuspiciousCorsPreflightToAdminApiRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R173",
            Name: "Suspicious CORS Preflight To Admin API",
            Category: "HttpApi",
            Description: "Detects cross-boundary CORS preflights to admin-like APIs with sensitive requested headers instead of every OPTIONS request.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R173.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R173",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "matched_conditions", "http.path" },
            positiveConditions: new[]
            {
                "The request must be a real CORS preflight with Access-Control-Request-Method present.",
                "The path must look like an admin or management API and the origin or requested headers must be suspicious.",
                "Ordinary same-site public API preflights should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic OPTIONS traffic with no CORS headers.",
                "Do not alert on public API preflights lacking admin-path or sensitive-header context."
            },
            minimumConfidence: 74,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+path",
            falsePositives: new[]
            {
                "Complex web applications and API gateways can legitimately preflight admin APIs across trusted domains."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive admin api cors preflight sample",
                "negative public api same-site preflight sample"
            });

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        public R173_SuspiciousCorsPreflightToAdminApiRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch171175Evidence.Http(record) || !NetworkBatch171175Evidence.Cors(record))
                return NoMatch();

            if (!NetworkBatch171175Evidence.Inbound(record))
                return NoMatch();

            if (!_replay.Observe(record, context.TimestampUtc)) return NoMatch();
            var path = HttpPath(record);
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "cors_preflight,admin_api_context,suspicious_origin_or_headers", "rule"),
                new("http.path", "[REDACTED]", "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "A cross-boundary CORS preflight targeted an admin-like API with suspicious origin or requested header context.",
                "Severity is Medium because this can indicate browser-based probing of privileged APIs or misconfigured cross-origin trust.",
                "Trusted multi-domain applications can legitimately preflight management APIs. Validate the origin against approved application domains.",
                "Confirm whether the origin domain is approved to call the targeted admin API.",
                "Review follow-on authenticated cross-origin requests, admin logins, or token-bearing traffic from the same source."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "Suspicious CORS preflight to admin API observed",
                "CorsAdminPreflight",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.20, "cors-preflight");
                    confidence.AddEvidence(0.20, "admin-api-context");
                    confidence.AddEvidence(0.16, "suspicious-origin-or-headers");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{NetworkBatch166170Evidence.Key(path)}");
        }
    }
}
