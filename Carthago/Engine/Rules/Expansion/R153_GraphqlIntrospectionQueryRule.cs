// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R153_GraphqlIntrospectionQueryRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R153_GraphqlIntrospectionQueryRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R153",
            Name: "GraphQL Introspection Query",
            Category: "HttpApi",
            Description: "Detects explicit GraphQL introspection requests on cross-boundary HTTP flows instead of relying on loose GraphQL text alone.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R153.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R153",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "matched_conditions", "http.path" },
            positiveConditions: new[]
            {
                "The record must have HTTP context and target a GraphQL endpoint.",
                "The URI, header summary, or parser info must contain an explicit introspection token such as __schema or IntrospectionQuery.",
                "The flow must cross an internal/external boundary to suppress ordinary internal developer traffic."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic GraphQL requests with no introspection indicators.",
                "Do not alert from AnyText-only inputs with no HTTP path or boundary context."
            },
            minimumConfidence: 72,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+host+path",
            falsePositives: new[]
            {
                "Developer tooling and approved schema inspection on sanctioned external GraphQL services can look similar."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive cross-boundary graphql introspection sample",
                "negative ordinary graphql query sample"
            });

        public R153_GraphqlIntrospectionQueryRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !IsGraphqlPath(record) || !HasGraphqlIntrospectionIndicator(record))
                return NoMatch();

            if (!IsCrossBoundary(record, out var outboundToExternal, out var inboundFromExternal))
                return NoMatch();

            var path = HttpPath(record);
            var matchedConditions = new List<string> { "graphql_path", "introspection_indicator", "boundary_crossing" };
            if (outboundToExternal) matchedConditions.Add("outbound_to_external");
            if (inboundFromExternal) matchedConditions.Add("inbound_from_external");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("http.path", string.IsNullOrWhiteSpace(path) ? "/" : path, "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "A GraphQL endpoint was reached with explicit schema introspection indicators across an internal/external boundary.",
                "Severity is Medium because introspection on exposed GraphQL endpoints often precedes API mapping, token abuse, or follow-on object enumeration.",
                "Approved developer tooling, schema explorers, or external partner APIs can generate similar requests. Validate whether the destination is sanctioned for schema discovery.",
                "Confirm whether the destination GraphQL service is approved for interactive schema inspection.",
                "Review the source user agent, process, and adjacent API requests for follow-on enumeration or token misuse."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "GraphQL introspection query observed",
                "GraphQLIntrospection",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "graphql-path");
                    confidence.AddEvidence(0.28, "introspection-indicator");
                    confidence.AddEvidence(0.18, "boundary-crossing");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{path}");
        }
    }
}
