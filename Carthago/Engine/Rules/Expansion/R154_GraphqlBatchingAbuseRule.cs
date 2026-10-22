// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R154_GraphqlBatchingAbuseRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R154_GraphqlBatchingAbuseRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R154",
            Name: "GraphQL Batching Abuse",
            Category: "HttpApi",
            Description: "Detects repeated GraphQL batch-style requests to the same endpoint instead of alerting on generic GraphQL traffic.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R154.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R154",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "matched_conditions", "count", "http.path" },
            positiveConditions: new[]
            {
                "The request must target a GraphQL endpoint with explicit batch-style indicators.",
                "The same source must repeat batch-style requests to the same GraphQL endpoint within the configured window.",
                "Single GraphQL requests without batching evidence should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on ordinary one-off GraphQL requests.",
                "Do not alert from AnyText-only inputs with no GraphQL path and no repeated request behavior."
            },
            minimumConfidence: 72,
            threshold: 5,
            window: TimeSpan.FromMinutes(2),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+host+path",
            falsePositives: new[]
            {
                "Some rich web clients legitimately batch GraphQL calls. Validate against approved applications before escalating."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive repeated graphql batching sample",
                "negative single graphql request sample"
            });

        public R154_GraphqlBatchingAbuseRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !HasMethod(record, "POST") || !IsGraphqlPath(record) || !HasGraphqlBatchingIndicator(record))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 120, 60, 3600));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 5, 3, 50);
            var path = HttpPath(record);
            var count = CountWindowEvents($"{Rule.RuleId}:{record.Source}:{BestHost(record)}:{path}", context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var matchedConditions = new List<string> { "graphql_path", "batching_indicator", "threshold_reached" };
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("http.path", string.IsNullOrWhiteSpace(path) ? "/" : path, "http"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "A source repeatedly issued GraphQL requests with explicit batching indicators to the same endpoint.",
                "Severity is Medium because repeated batch-style GraphQL calls can accelerate schema and object discovery or amplify scraping against exposed APIs.",
                "Modern SPAs sometimes batch GraphQL operations. Validate the source user agent and destination service against approved application behavior.",
                "Review the same source for adjacent GraphQL introspection, object enumeration, or token misuse.",
                "Confirm whether GraphQL batching is expected for this endpoint and client."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "Repeated GraphQL batching pattern observed",
                "GraphQLBatching",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "graphql-path");
                    confidence.AddEvidence(0.22, "batching-indicator");
                    confidence.AddEvidence(0.20, "threshold-reached");
                },
                count,
                window,
                $"{record.Source}:{BestHost(record)}:{path}");
        }
    }
}
