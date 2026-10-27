// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R155_RestApiEnumerationBurstRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R155_RestApiEnumerationBurstRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R155",
            Name: "REST API Enumeration Burst",
            Category: "HttpApi",
            Description: "Detects cross-boundary bursts of distinct REST API resource requests instead of alerting on isolated API calls.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R155.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R155",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "matched_conditions", "count", "http.path" },
            positiveConditions: new[]
            {
                "The requests must target API-style paths over HTTP.",
                "The same source must probe many distinct API resources within the configured window.",
                "Ordinary browser-driven browsing to public external APIs should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on a single API request or low-volume API browsing.",
                "Do not alert on outbound browser traffic to external APIs when there is no strong enumeration burst."
            },
            minimumConfidence: 72,
            threshold: 6,
            window: TimeSpan.FromMinutes(3),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "uri",
            falsePositives: new[]
            {
                "Internal QA sweeps, sanctioned security tests, and automated integration tests can enumerate API resources quickly."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive distinct api enumeration burst sample",
                "negative external browser api browsing sample"
            });

        public R155_RestApiEnumerationBurstRule()
            : base(Rule, Profile)
        {
        }

        private readonly NetworkBatch151155DistinctWindow _observations = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch151155Evidence.HttpRequest(record)
                || !HasMethod(record, "GET", "HEAD", "OPTIONS")
                || !NetworkBatch151155Evidence.ApiResourcePath(record, out var path)
                || !NetworkBatch126130Evidence.CrossBoundary(record, out var outboundToExternal, out var inboundFromExternal))
                return NoMatch();

            if (outboundToExternal && IsBrowserLikeUserAgent(record))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 180, 60, 3600));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 6, 4, 100);
            var key = $"{record.Source}:{record.Destination}:{record.DestinationPort}:{record.HttpHost}";
            if (!_observations.Observe(key, record.Id, path, context.TimestampUtc, window, out var distinct)
                || distinct < threshold)
                return NoMatch();

            var conditions = new List<string> { "typed_http_request", "distinct_api_paths", "cross_boundary" };
            if (outboundToExternal) conditions.Add("outbound_to_external");
            if (inboundFromExternal) conditions.Add("inbound_from_external");
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", conditions), "rule"),
                new("http.path", "/api/[REDACTED]", "http"),
                new("count", distinct.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "An attributed cross-boundary client visited many distinct API resource paths within a short window.",
                "Severity is Medium because API enumeration can indicate reconnaissance or scraping.",
                "QA, integration tests and authorized scanners can exhibit the same shape.",
                "Correlate with permissions, responses and explicit authorization.",
                "Review whether the source is an approved scanner or integration job."));
            return MatchHttpApi(context, SeverityLevel.Medium, "REST API resource enumeration burst",
                "ApiEnumeration", evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "api-path");
                    confidence.AddEvidence(0.24, "distinct-uri-threshold");
                    confidence.AddEvidence(0.16, "boundary-crossing");
                }, distinct, window, NetworkBatch131135Evidence.Fingerprint(key));
        }
    }
}
