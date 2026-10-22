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

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !HasMethod(record, "GET", "HEAD", "OPTIONS") || !IsLikelyApiPath(record))
                return NoMatch();

            if (!IsCrossBoundary(record, out var outboundToExternal, out var inboundFromExternal))
                return NoMatch();

            if (outboundToExternal && IsBrowserLikeUserAgent(record))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 180, 60, 3600));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 6, 4, 100);
            var distinct = CountDistinctValues($"{Rule.RuleId}:{record.Source}:{BestHost(record)}", ApiProbeKey(record), context.TimestampUtc, window);
            if (distinct < threshold)
                return NoMatch();

            var path = HttpPath(record);
            var matchedConditions = new List<string> { "api_path", "distinct_uri_threshold", "boundary_crossing" };
            if (inboundFromExternal) matchedConditions.Add("inbound_from_external");
            if (outboundToExternal) matchedConditions.Add("outbound_to_external");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("http.path", string.IsNullOrWhiteSpace(path) ? "/" : path, "http"),
                new("count", distinct.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "A cross-boundary source rapidly touched many distinct API resources in a short window.",
                "Severity is Medium because fast enumeration of API resources often indicates discovery, scraping, or credentialed post-auth reconnaissance.",
                "Approved testing pipelines, QA sweeps, or inventory jobs can resemble API enumeration bursts. Validate the source process or user agent before escalating.",
                "Review adjacent API authentication, GraphQL, and documentation probe activity from the same source.",
                "Confirm whether the source is an approved test runner, scanner, or integration job."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "REST API enumeration burst observed",
                "ApiEnumeration",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "api-path");
                    confidence.AddEvidence(0.24, "distinct-uri-threshold");
                    confidence.AddEvidence(0.16, "boundary-crossing");
                },
                distinct,
                window,
                $"{record.Source}:{BestHost(record)}");
        }
    }
}
