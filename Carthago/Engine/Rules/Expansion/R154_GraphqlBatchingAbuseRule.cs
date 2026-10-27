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

        private readonly NetworkBatch141145Window _observations = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch151155Evidence.HttpRequest(record)
                || !HasMethod(record, "POST")
                || !NetworkBatch151155Evidence.GraphqlPath(record)
                || !NetworkBatch151155Evidence.GraphqlBatchSummary(record))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 120, 60, 3600));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 5, 3, 50);
            var key = $"{record.Source}:{record.Destination}:{record.DestinationPort}:{record.HttpHost}:graphql";
            if (!_observations.Observe(key, record.Id, context.TimestampUtc, window, out var count)
                || count < threshold)
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "typed_http_post,graphql_endpoint,bounded_batch_summary,independent_threshold", "rule"),
                new("http.path", "/graphql", "http"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "A single attributed source repeated GraphQL POST requests whose metadata indicated batched operations.",
                "Severity is Medium because sustained batching can amplify API probing, but is also common in approved apps.",
                "The current model has no trusted GraphQL body field; Info-only batch labels require independent confirmation.",
                "Validate the originating client and the server's batching policy.",
                "Correlate with distinct GraphQL operations, errors and rate limits."));
            return MatchHttpApi(context, SeverityLevel.Medium, "Repeated GraphQL batching summaries observed",
                "GraphQLBatching", evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "graphql-path");
                    confidence.AddEvidence(0.22, "batching-indicator");
                    confidence.AddEvidence(0.20, "threshold-reached");
                }, count, window, NetworkBatch131135Evidence.Fingerprint(key));
        }
    }
}
