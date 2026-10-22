// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R175_HttpRequestSmugglingIndicatorRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R175_HttpRequestSmugglingIndicatorRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R175",
            Name: "HTTP Request Smuggling Indicator",
            Category: "HttpApi",
            Description: "Detects concrete conflicting HTTP framing headers such as CL+TE or multiple Content-Length values instead of matching the word chunked alone.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R175.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R175",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "matched_conditions", "http.method", "smuggling.mode" },
            positiveConditions: new[]
            {
                "The request must contain concrete conflicting framing semantics such as CL+TE or multiple Content-Length values.",
                "The request should be a body-bearing method such as POST, PUT, or PATCH.",
                "Ordinary chunked or Content-Length-only traffic should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on standard single Content-Length requests.",
                "Do not alert on generic mentions of chunked without framing conflicts."
            },
            minimumConfidence: 82,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+mode",
            falsePositives: new[]
            {
                "Request smuggling test suites, proxy conformance tools, and replay labs can intentionally send conflicting framing headers."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive conflicting framing header sample",
                "negative standard content length sample"
            });

        public R175_HttpRequestSmugglingIndicatorRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !HasMethod(record, "POST", "PUT", "PATCH"))
                return NoMatch();

            if (!HasRequestSmugglingIndicators(record, out var mode))
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "body_bearing_method,conflicting_http_framing", "rule"),
                new("http.method", record.HttpMethod ?? "unknown", "http"),
                new("smuggling.mode", mode, "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "An HTTP request used conflicting framing semantics consistent with request smuggling attempts.",
                "Severity is High because CL/TE ambiguities can desynchronize front-end and back-end parsers, enabling cache poisoning or request tunneling.",
                "Protocol conformance tests, proxy validation, and security labs can intentionally send these header combinations.",
                "Confirm whether the source is an approved test tool or whether the target is a production-facing HTTP stack.",
                "Review adjacent Host header, CORS, upload, or admin-path activity from the same source."));

            return MatchHttpApi(
                context,
                SeverityLevel.High,
                "Conflicting HTTP framing observed",
                "HttpRequestSmuggling",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "body-bearing-method");
                    confidence.AddEvidence(0.34, "conflicting-http-framing");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{mode}");
        }
    }
}
