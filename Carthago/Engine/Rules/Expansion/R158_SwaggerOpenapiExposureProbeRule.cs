// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R158_SwaggerOpenapiExposureProbeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R158_SwaggerOpenapiExposureProbeRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R158",
            Name: "Swagger OpenAPI Exposure Probe",
            Category: "HttpApi",
            Description: "Detects cross-boundary access to Swagger or OpenAPI discovery endpoints rather than generic documentation browsing.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R158.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R158",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "matched_conditions", "http.path" },
            positiveConditions: new[]
            {
                "The flow must cross an internal/external boundary.",
                "The request must target an exact Swagger or OpenAPI discovery path.",
                "Known public documentation hosts should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on browsing to public Swagger or OpenAPI documentation providers.",
                "Do not alert on generic /docs paths that are not Swagger or OpenAPI discovery endpoints."
            },
            minimumConfidence: 72,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+path",
            falsePositives: new[]
            {
                "Approved API gateways may intentionally expose Swagger or OpenAPI documents for partners or developers."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive swagger discovery probe sample",
                "negative public swagger documentation host sample"
            });

        public R158_SwaggerOpenapiExposureProbeRule()
            : base(Rule, Profile)
        {
        }

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch156165Evidence.Http(record) || !HasMethod(record, "GET", "HEAD", "OPTIONS") || !NetworkBatch156165Evidence.Swagger(record) || IsBenignSwaggerHost(record))
                return NoMatch();

            if (!NetworkBatch126130Evidence.CrossBoundary(record, out _, out var inbound) || !inbound)
                return NoMatch();

            var path = HttpPath(record);
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "swagger_or_openapi_path,boundary_crossing", "rule"),
                new("http.routeCategory", "swagger_openapi", "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "A cross-boundary request targeted a Swagger or OpenAPI discovery endpoint.",
                "Severity is Medium because exposed API specifications materially accelerate endpoint discovery and post-auth enumeration.",
                "Some partner-facing APIs intentionally publish OpenAPI docs. Validate whether the host is meant to expose interactive or raw API specs.",
                "Confirm whether the target host should publicly expose Swagger or OpenAPI definitions.",
                "Review follow-on API enumeration, token abuse, or admin-path access from the same source."));

            if (!_replay.Observe(record, context.TimestampUtc)) return NoMatch();

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "Swagger/OpenAPI discovery endpoint probed",
                "SwaggerExposure",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.26, "swagger-path");
                    confidence.AddEvidence(0.18, "boundary-crossing");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{path}");
        }
    }
}
